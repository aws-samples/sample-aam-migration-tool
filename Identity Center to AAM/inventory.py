"""Inventory module: discover IdC permission sets and account assignments."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Iterable

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from audit_logger import AuditLogger
from aws_session import HubContext, boto_config
from config import Config
from models import (
    AccountAssignmentRecord,
    CustomerManagedPolicyReference,
    Inventory,
    PermissionSetRecord,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _safe(fn, *args, default=None, **kwargs):
    """Run a callable, returning (result, error). On AWS exceptions, return
    (default, exception). The caller decides how to react."""
    try:
        return fn(*args, **kwargs), None
    except (ClientError, BotoCoreError) as exc:  # noqa: BLE001
        return default, exc


def _paginate(client, op_name: str, **kwargs) -> Iterable[dict[str, Any]]:
    """Paginate any boto3 operation and yield page dicts."""
    paginator = client.get_paginator(op_name)
    for page in paginator.paginate(**kwargs):
        yield page


def _is_throttle(exc: BaseException) -> bool:
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        return code in {"ThrottlingException", "Throttling", "TooManyRequestsException", "RequestLimitExceeded"}
    return False


# ─── Inventory module ─────────────────────────────────────────────────────────

class InventoryModule:
    def __init__(self, hub: HubContext, cfg: Config, audit: AuditLogger) -> None:
        self.hub = hub
        self.cfg = cfg
        self.audit = audit
        cfg_obj = boto_config(cfg.workers)
        self.sso_admin = hub.session.client("sso-admin", region_name=cfg.region, config=cfg_obj)
        self.identity_store = hub.session.client(
            "identitystore", region_name=cfg.region, config=cfg_obj
        )

    # ── Discovery ────────────────────────────────────────────────────────────

    def discover_idc_instance(self) -> tuple[str, str]:
        """Return (instance_arn, identity_store_id) (Req 7.2)."""
        if self.cfg.aam_idc_instance_arn:
            instance_arn = self.cfg.aam_idc_instance_arn
            for page in _paginate(self.sso_admin, "list_instances"):
                for inst in page.get("Instances", []):
                    if inst["InstanceArn"] == instance_arn:
                        return instance_arn, inst["IdentityStoreId"]
            raise RuntimeError(
                f"Configured IdC instance ARN {instance_arn} not found in account "
                f"{self.hub.account_id}"
            )

        instances: list[dict[str, Any]] = []
        for page in _paginate(self.sso_admin, "list_instances"):
            instances.extend(page.get("Instances", []))
        if not instances:
            raise RuntimeError("No IAM Identity Center instance found in this account")
        if len(instances) > 1:
            self.audit.log_success(
                "discover_idc_instance",
                instances[0]["InstanceArn"],
                note="multiple IdC instances; using first",
                count=len(instances),
            )
        return instances[0]["InstanceArn"], instances[0]["IdentityStoreId"]

    # ── Permission sets (Req 2.1–2.9) ────────────────────────────────────────

    def list_permission_sets(self, instance_arn: str) -> list[str]:
        arns: list[str] = []
        for page in _paginate(self.sso_admin, "list_permission_sets", InstanceArn=instance_arn):
            arns.extend(page.get("PermissionSets", []))
        return arns

    def describe_permission_set(self, instance_arn: str, ps_arn: str) -> PermissionSetRecord:
        # Each fetch is wrapped so any subordinate failure marks the record
        # incomplete but does not abort.
        describe_resp, describe_err = _safe(
            self.sso_admin.describe_permission_set,
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn,
        )
        inline_resp, inline_err = _safe(
            self.sso_admin.get_inline_policy_for_permission_set,
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn,
        )
        managed_arns: list[str] = []
        managed_err: BaseException | None = None
        try:
            for page in _paginate(
                self.sso_admin,
                "list_managed_policies_in_permission_set",
                InstanceArn=instance_arn,
                PermissionSetArn=ps_arn,
            ):
                for p in page.get("AttachedManagedPolicies", []):
                    arn = p.get("Arn")
                    if arn:
                        managed_arns.append(arn)
        except (ClientError, BotoCoreError) as exc:  # noqa: BLE001
            managed_err = exc

        cmp_refs: list[CustomerManagedPolicyReference] = []
        cmp_err: BaseException | None = None
        try:
            for page in _paginate(
                self.sso_admin,
                "list_customer_managed_policy_references_in_permission_set",
                InstanceArn=instance_arn,
                PermissionSetArn=ps_arn,
            ):
                for ref in page.get("CustomerManagedPolicyReferences", []):
                    cmp_refs.append(
                        CustomerManagedPolicyReference(
                            name=ref.get("Name", ""),
                            path=ref.get("Path", "/"),
                        )
                    )
        except (ClientError, BotoCoreError) as exc:  # noqa: BLE001
            cmp_err = exc

        boundary_resp, boundary_err = _safe(
            self.sso_admin.get_permissions_boundary_for_permission_set,
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn,
        )

        # Build the record. If Describe failed we have no name — use a placeholder.
        ps_dict = (describe_resp or {}).get("PermissionSet", {})
        name = ps_dict.get("Name", ps_arn.rsplit("/", 1)[-1])
        description = ps_dict.get("Description", "")
        session_duration = ps_dict.get("SessionDuration", "PT1H")

        inline_doc: dict | None = None
        inline_text = (inline_resp or {}).get("InlinePolicy", "") if inline_resp else ""
        if inline_text:
            try:
                inline_doc = json.loads(inline_text)
            except json.JSONDecodeError as exc:
                inline_err = exc
                inline_doc = None

        boundary: dict | None = None
        if boundary_resp and boundary_resp.get("PermissionsBoundary"):
            boundary = dict(boundary_resp["PermissionsBoundary"])

        # ResourceNotFoundException for the permission boundary is normal (none set).
        if boundary_err and isinstance(boundary_err, ClientError):
            if boundary_err.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                boundary_err = None

        errors = [
            ("describe", describe_err),
            ("inline_policy", inline_err),
            ("managed_policies", managed_err),
            ("cmp_references", cmp_err),
            ("permission_boundary", boundary_err),
        ]
        incomplete = any(e is not None for _, e in errors)
        error_reason = "; ".join(
            f"{label}: {type(err).__name__}: {err}"
            for label, err in errors
            if err is not None
        )

        record = PermissionSetRecord(
            arn=ps_arn,
            name=name,
            description=description,
            session_duration=session_duration,
            inline_policy=inline_doc,
            aws_managed_policy_arns=tuple(managed_arns),
            customer_managed_policy_references=tuple(cmp_refs),
            permission_boundary=boundary,
            incomplete=incomplete,
            error_reason=error_reason,
        )

        if incomplete:
            self.audit.log(
                "inventory_permission_set",
                ps_arn,
                "FAILURE",
                error_detail=error_reason,
            )
        else:
            self.audit.log_success(
                "inventory_permission_set",
                ps_arn,
                name=name,
            )
        return record

    # ── Account assignments (Req 3.1–3.4) ────────────────────────────────────

    def list_assignments_for_permission_set(
        self,
        instance_arn: str,
        ps_arn: str,
        identity_store_id: str,
        filter_account_ids: list[str] | None = None,
    ) -> list[AccountAssignmentRecord]:
        """List assignments for a permission set.

        When ``filter_account_ids`` is provided (single/multi mode), only the
        specified accounts are queried — skipping the ListAccountsForProvisioned
        call entirely. When None (org mode), all provisioned accounts are queried.
        """
        if filter_account_ids is not None:
            accounts = filter_account_ids
        else:
            accounts = []
            try:
                for page in _paginate(
                    self.sso_admin,
                    "list_accounts_for_provisioned_permission_set",
                    InstanceArn=instance_arn,
                    PermissionSetArn=ps_arn,
                ):
                    accounts.extend(page.get("AccountIds", []))
            except (ClientError, BotoCoreError) as exc:  # noqa: BLE001
                self.audit.log_failure("inventory_assignments", ps_arn, exc)
                return []

        results: list[AccountAssignmentRecord] = []
        # Resolve display names lazily and cache them per-run.
        name_cache: dict[tuple[str, str], str] = {}

        for account_id in accounts:
            try:
                for page in _paginate(
                    self.sso_admin,
                    "list_account_assignments",
                    InstanceArn=instance_arn,
                    AccountId=account_id,
                    PermissionSetArn=ps_arn,
                ):
                    for a in page.get("AccountAssignments", []):
                        principal_type = a["PrincipalType"]  # USER | GROUP
                        principal_id = a["PrincipalId"]
                        display_name = self._resolve_display_name(
                            identity_store_id,
                            principal_type,
                            principal_id,
                            name_cache,
                        )
                        results.append(
                            AccountAssignmentRecord(
                                permission_set_arn=ps_arn,
                                account_id=account_id,
                                principal_type=principal_type,  # type: ignore[arg-type]
                                principal_id=principal_id,
                                principal_display_name=display_name,
                            )
                        )
            except (ClientError, BotoCoreError) as exc:  # noqa: BLE001
                self.audit.log_failure(
                    "inventory_assignments",
                    f"{ps_arn}@{account_id}",
                    exc,
                )

        for r in results:
            self.audit.log_success(
                "inventory_assignment",
                f"{r.permission_set_arn}@{r.account_id}#{r.principal_id}",
                principal_type=r.principal_type,
            )
        return results

    def _resolve_display_name(
        self,
        identity_store_id: str,
        principal_type: str,
        principal_id: str,
        cache: dict[tuple[str, str], str],
    ) -> str:
        key = (principal_type, principal_id)
        if key in cache:
            return cache[key]
        try:
            if principal_type == "USER":
                resp = self.identity_store.describe_user(
                    IdentityStoreId=identity_store_id, UserId=principal_id
                )
                name = resp.get("UserName") or resp.get("DisplayName") or principal_id
            else:
                resp = self.identity_store.describe_group(
                    IdentityStoreId=identity_store_id, GroupId=principal_id
                )
                name = resp.get("DisplayName") or resp.get("GroupName") or principal_id
        except (ClientError, BotoCoreError) as exc:  # noqa: BLE001
            self.audit.log_failure(
                "resolve_principal_display_name",
                principal_id,
                exc,
                principal_type=principal_type,
            )
            name = principal_id  # Req 3.4 fallback
        cache[key] = name or principal_id
        return cache[key]

    # ── Orchestration ────────────────────────────────────────────────────────

    def list_permission_sets_for_account(self, instance_arn: str, account_id: str) -> list[str]:
        """List only permission sets provisioned to a specific account.

        Uses ListPermissionSetsProvisionedToAccount — far more efficient than
        listing all permission sets and then filtering when you only care about
        one or a few accounts.
        """
        arns: list[str] = []
        for page in _paginate(
            self.sso_admin,
            "list_permission_sets_provisioned_to_account",
            InstanceArn=instance_arn,
            AccountId=account_id,
        ):
            arns.extend(page.get("PermissionSets", []))
        return arns

    def run(self) -> Inventory:
        instance_arn, identity_store_id = self.discover_idc_instance()
        self.audit.log_success("discover_idc_instance", instance_arn, identity_store_id=identity_store_id)

        account_scope = self.cfg.account_scope  # "single" | "multi" | "org"
        target_account_ids: list[str] = []

        if account_scope == "single":
            # Single-account: use the hub account ID as the sole target.
            target_account_ids = [self.hub.account_id]
        elif account_scope == "multi":
            # Multi-account: use target_account_ids if specified, fall back to account_ids.
            target_account_ids = list(self.cfg.target_account_ids or self.cfg.account_ids)

        # ── Determine permission sets to describe ────────────────────────────
        if account_scope in ("single", "multi"):
            # Optimized path: only list permission sets provisioned to the
            # target account(s). Avoids scanning the entire IdC instance.
            ps_arns_set: set[str] = set()
            for acct in target_account_ids:
                ps_arns_set.update(
                    self.list_permission_sets_for_account(instance_arn, acct)
                )
            ps_arns = sorted(ps_arns_set)
            self.audit.log_success(
                "list_permission_sets_for_accounts",
                instance_arn,
                count=len(ps_arns),
                accounts=len(target_account_ids),
            )
        else:
            # Org mode: list ALL permission sets (existing behavior).
            ps_arns = self.list_permission_sets(instance_arn)
            self.audit.log_success("list_permission_sets", instance_arn, count=len(ps_arns))

        records: list[PermissionSetRecord] = []
        assignments: list[AccountAssignmentRecord] = []

        with ThreadPoolExecutor(max_workers=max(1, self.cfg.workers)) as pool:
            describe_futures = {
                pool.submit(self.describe_permission_set, instance_arn, arn): arn
                for arn in ps_arns
            }
            for fut in as_completed(describe_futures):
                arn = describe_futures[fut]
                try:
                    records.append(fut.result())
                except Exception as exc:  # noqa: BLE001
                    self.audit.log_failure("inventory_permission_set", arn, exc)
                    records.append(
                        PermissionSetRecord(
                            arn=arn,
                            name=arn.rsplit("/", 1)[-1],
                            description="",
                            session_duration="PT1H",
                            inline_policy=None,
                            aws_managed_policy_arns=(),
                            customer_managed_policy_references=(),
                            permission_boundary=None,
                            incomplete=True,
                            error_reason=f"{type(exc).__name__}: {exc}",
                        )
                    )

            assign_futures = {
                pool.submit(
                    self.list_assignments_for_permission_set,
                    instance_arn,
                    arn,
                    identity_store_id,
                    target_account_ids if account_scope in ("single", "multi") else None,
                ): arn
                for arn in ps_arns
            }
            for fut in as_completed(assign_futures):
                arn = assign_futures[fut]
                try:
                    assignments.extend(fut.result())
                except Exception as exc:  # noqa: BLE001
                    self.audit.log_failure("inventory_assignments", arn, exc)

        records.sort(key=lambda r: r.arn)
        assignments.sort(
            key=lambda a: (a.permission_set_arn, a.account_id, a.principal_id)
        )

        inventory = Inventory(
            hub_account_id=self.hub.account_id,
            idc_instance_arn=instance_arn,
            identity_store_id=identity_store_id,
            permission_sets=tuple(records),
            assignments=tuple(assignments),
            run_id=self.cfg.run_id,
            captured_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

        path = self.persist(inventory, self.cfg.inventory_output_path)
        self.audit.log_success(
            "inventory_complete",
            inventory.idc_instance_arn,
            inventory_path=path,
            permission_set_count=len(records),
            assignment_count=len(assignments),
        )
        return inventory

    def persist(self, inventory: Inventory, output_path: str | None) -> str:
        path = output_path or f"inventory_{inventory.run_id}.json"
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(inventory.to_json())
        return path
