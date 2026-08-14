"""Role creator: recreate IdC permission sets as IAM roles in target accounts."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from audit_logger import AuditLogger
from aws_session import boto_config
from config import Config, render_cmp_name
from models import (
    CustomerManagedPolicyReference,
    Inventory,
    PermissionSetRecord,
    RoleCreationResult,
)


SessionFactory = Callable[[str], boto3.Session]


class RoleCreator:
    def __init__(
        self,
        cfg: Config,
        audit: AuditLogger,
        session_factory: SessionFactory,
        role_names: dict[str, str] | None = None,
        *,
        iac_generator: "object | None" = None,
    ) -> None:
        self.cfg = cfg
        self.audit = audit
        self.session_factory = session_factory
        # permission_set_arn -> RoleName resolved from the migration plan (Req 6.1).
        self.role_names: dict[str, str] = dict(role_names or {})
        self.iac_generator = iac_generator
        self._trust_policy_doc: str | None = None

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _role_name_for(self, ps: PermissionSetRecord) -> str | None:
        """Role name comes from the migration plan, never a template (Req 6.1)."""
        return self.role_names.get(ps.arn)

    def _load_trust_policy(self) -> str:
        if self._trust_policy_doc is not None:
            return self._trust_policy_doc
        if not self.cfg.trust_policy_path:
            raise RuntimeError("Trust policy path is required for role creation")
        with open(self.cfg.trust_policy_path, "r", encoding="utf-8") as f:
            text = f.read()
        # Validate JSON shape early.
        doc = json.loads(text)

        # Inject confused-deputy conditions when AAM application ARN is available
        if self.cfg.aam_application_arn:
            app_arn = self.cfg.aam_application_arn
            parts = app_arn.split(":")
            source_account = parts[4] if len(parts) >= 5 else ""
            for stmt in doc.get("Statement", []):
                principal = stmt.get("Principal", {})
                svc = principal.get("Service", "")
                if svc == "account-access.amazonaws.com":
                    condition = stmt.setdefault("Condition", {})
                    str_eq = condition.setdefault("StringEquals", {})
                    if source_account:
                        str_eq["aws:SourceAccount"] = source_account
                    str_eq["aws:SourceArn"] = app_arn
            text = json.dumps(doc)

        self._trust_policy_doc = text
        return text

    def role_arn(self, account_id: str, role_path: str, role_name: str) -> str:
        path = role_path if role_path.endswith("/") else role_path + "/"
        return f"arn:aws:iam::{account_id}:role{path}{role_name}"

    def cmp_arn_from_reference(
        self, account_id: str, ref: CustomerManagedPolicyReference
    ) -> str:
        path = ref.path if ref.path.endswith("/") else ref.path + "/"
        if not path.startswith("/"):
            path = "/" + path
        return f"arn:aws:iam::{account_id}:policy{path}{ref.name}"

    def _tags_for_create_role(self) -> list[dict[str, str]]:
        return [{"Key": k, "Value": v} for k, v in sorted(self.cfg.role_tags.items())]

    # ── Per-permission-set / per-account creation ────────────────────────────

    def create_role_for_assignment_set(
        self,
        ps: PermissionSetRecord,
        account_id: str,
    ) -> RoleCreationResult:
        role_name = self._role_name_for(ps)
        if not role_name:
            # No role name in the migration plan for this permission set (Req 6.1).
            self.audit.log(
                "create_role",
                f"{ps.arn}@{account_id}",
                "FAILURE",
                error_detail="no role name in migration plan for permission set",
            )
            return RoleCreationResult(
                permission_set_arn=ps.arn,
                account_id=account_id,
                role_name="",
                role_arn=None,
                status="FAILED",
                error_detail="no role name in migration plan for permission set",
            )
        target_role_arn = self.role_arn(account_id, self.cfg.role_path, role_name)

        try:
            session = self.session_factory(account_id)
        except (ClientError, BotoCoreError) as exc:  # noqa: BLE001 - fail-and-continue (Req 1.5)
            self.audit.log_failure("assume_spoke_session", account_id, exc)
            return RoleCreationResult(
                permission_set_arn=ps.arn,
                account_id=account_id,
                role_name=role_name,
                role_arn=None,
                status="FAILED",
                error_detail=f"{type(exc).__name__}: {exc}",
            )

        iam = session.client("iam", config=boto_config(self.cfg.workers))

        # ── Idempotency check (Req 6.8, 11.1) ────────────────────────────────
        existing = self._get_existing_role(iam, role_name, target_role_arn, ps.arn, account_id)
        if existing is not None:
            return existing

        # ── Create role ──────────────────────────────────────────────────────
        try:
            trust_doc = self._load_trust_policy()
        except Exception as exc:  # noqa: BLE001
            self.audit.log_failure("load_trust_policy", target_role_arn, exc)
            return RoleCreationResult(
                permission_set_arn=ps.arn,
                account_id=account_id,
                role_name=role_name,
                role_arn=None,
                status="FAILED",
                error_detail=f"{type(exc).__name__}: {exc}",
            )

        try:
            iam.create_role(
                RoleName=role_name,
                Path=self.cfg.role_path,
                AssumeRolePolicyDocument=trust_doc,
                Description=f"Created by IdC-to-AAM tool for permission set {ps.name}",
                Tags=self._tags_for_create_role(),
            )
            self.audit.log_success(
                "create_role",
                target_role_arn,
                permission_set_arn=ps.arn,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "EntityAlreadyExists":
                # Race condition with idempotency check; re-treat as EXISTING.
                existing = self._get_existing_role(iam, role_name, target_role_arn, ps.arn, account_id)
                if existing is not None:
                    return existing
            self.audit.log_failure("create_role", target_role_arn, exc)
            return RoleCreationResult(
                permission_set_arn=ps.arn,
                account_id=account_id,
                role_name=role_name,
                role_arn=None,
                status="FAILED",
                error_detail=f"{type(exc).__name__}: {exc}",
            )

        attached_managed = self._attach_managed_policies(iam, role_name, ps, target_role_arn)
        inline_attached, converted_cmp_arn = self._attach_inline_policy(
            iam, role_name, ps, account_id, target_role_arn
        )
        attached_cmp_arns = self._attach_customer_managed_policies(
            iam, role_name, ps, account_id, target_role_arn
        )
        permission_boundary_arn = self._attach_permission_boundary(
            iam, role_name, target_role_arn
        )

        return RoleCreationResult(
            permission_set_arn=ps.arn,
            account_id=account_id,
            role_name=role_name,
            role_arn=target_role_arn,
            status="CREATED",
            attached_managed_policies=tuple(attached_managed),
            inline_policy_attached=inline_attached,
            converted_cmp_arn=converted_cmp_arn,
            attached_cmp_arns=tuple(attached_cmp_arns),
            permission_boundary_arn=permission_boundary_arn,
        )

    # ── Sub-steps ────────────────────────────────────────────────────────────

    def _get_existing_role(
        self,
        iam,
        role_name: str,
        target_role_arn: str,
        permission_set_arn: str,
        account_id: str,
    ) -> RoleCreationResult | None:
        try:
            resp = iam.get_role(RoleName=role_name)
            existing_arn = resp["Role"]["Arn"]
            self.audit.log_success(
                "role_already_exists",
                existing_arn,
                permission_set_arn=permission_set_arn,
            )
            return RoleCreationResult(
                permission_set_arn=permission_set_arn,
                account_id=account_id,
                role_name=role_name,
                role_arn=existing_arn,
                status="EXISTING",
                permission_boundary_arn=self.cfg.permission_boundary_arn,
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return None
            self.audit.log_failure("get_role", target_role_arn, exc)
            raise

    def _attach_managed_policies(
        self,
        iam,
        role_name: str,
        ps: PermissionSetRecord,
        target_role_arn: str,
    ) -> list[str]:
        attached: list[str] = []
        for arn in ps.aws_managed_policy_arns:
            try:
                iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
                attached.append(arn)
                self.audit.log_success("attach_managed_policy", target_role_arn, policy_arn=arn)
            except (ClientError, BotoCoreError) as exc:  # noqa: BLE001
                self.audit.log_failure(
                    "attach_managed_policy", target_role_arn, exc, policy_arn=arn
                )
        return attached

    def _attach_inline_policy(
        self,
        iam,
        role_name: str,
        ps: PermissionSetRecord,
        account_id: str,
        target_role_arn: str,
    ) -> tuple[bool, str | None]:
        if not ps.inline_policy:
            return False, None

        if not self.cfg.convert_inline_to_cmp:
            try:
                iam.put_role_policy(
                    RoleName=role_name,
                    PolicyName=f"{role_name}-inline",
                    PolicyDocument=json.dumps(ps.inline_policy),
                )
                self.audit.log_success("put_inline_policy", target_role_arn)
                return True, None
            except (ClientError, BotoCoreError) as exc:  # noqa: BLE001
                self.audit.log_failure("put_inline_policy", target_role_arn, exc)
                return False, None

        # Convert inline to CMP (Req 5.7)
        cmp_name = render_cmp_name(self.cfg.cmp_name_template, ps.name)
        try:
            create_resp = iam.create_policy(
                PolicyName=cmp_name,
                Path=self.cfg.role_path,
                PolicyDocument=json.dumps(ps.inline_policy),
                Description=f"Converted inline from permission set {ps.name}",
            )
            cmp_arn = create_resp["Policy"]["Arn"]
            self.audit.log_success("create_cmp_from_inline", cmp_arn)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "EntityAlreadyExists":
                cmp_arn = f"arn:aws:iam::{account_id}:policy{self.cfg.role_path}{cmp_name}"
                self.audit.log_success("cmp_already_exists", cmp_arn)
            else:
                self.audit.log_failure("create_cmp_from_inline", cmp_name, exc)
                return False, None
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=cmp_arn)
            self.audit.log_success("attach_converted_cmp", target_role_arn, policy_arn=cmp_arn)
            return True, cmp_arn
        except (ClientError, BotoCoreError) as exc:  # noqa: BLE001
            self.audit.log_failure("attach_converted_cmp", target_role_arn, exc, policy_arn=cmp_arn)
            return False, cmp_arn

    def _attach_customer_managed_policies(
        self,
        iam,
        role_name: str,
        ps: PermissionSetRecord,
        account_id: str,
        target_role_arn: str,
    ) -> list[str]:
        attached: list[str] = []
        for ref in ps.customer_managed_policy_references:
            arn = self.cmp_arn_from_reference(account_id, ref)
            try:
                iam.get_policy(PolicyArn=arn)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code == "NoSuchEntity":
                    self.audit.log(
                        "skip_missing_cmp",
                        target_role_arn,
                        "FAILURE",
                        error_detail=f"CMP {arn} does not exist in account {account_id}",
                        extra={"policy_arn": arn},
                    )
                    continue
                self.audit.log_failure("get_cmp_policy", arn, exc)
                continue

            try:
                iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
                attached.append(arn)
                self.audit.log_success("attach_cmp", target_role_arn, policy_arn=arn)
            except (ClientError, BotoCoreError) as exc:  # noqa: BLE001
                self.audit.log_failure("attach_cmp", target_role_arn, exc, policy_arn=arn)
        return attached

    def _attach_permission_boundary(
        self,
        iam,
        role_name: str,
        target_role_arn: str,
    ) -> str | None:
        if not self.cfg.permission_boundary_arn:
            return None
        try:
            iam.put_role_permissions_boundary(
                RoleName=role_name,
                PermissionsBoundary=self.cfg.permission_boundary_arn,
            )
            self.audit.log_success(
                "put_role_permissions_boundary",
                target_role_arn,
                permission_boundary_arn=self.cfg.permission_boundary_arn,
            )
            return self.cfg.permission_boundary_arn
        except (ClientError, BotoCoreError) as exc:  # noqa: BLE001
            self.audit.log_failure(
                "put_role_permissions_boundary",
                target_role_arn,
                exc,
                permission_boundary_arn=self.cfg.permission_boundary_arn,
            )
            return None

    # ── Orchestration ────────────────────────────────────────────────────────

    def run(self, inventory: Inventory) -> list[RoleCreationResult]:
        # In generate-iac mode, emit IaC and return planned-role results without
        # any mutating IAM call (Req 7.5, 9.1).
        if self.cfg.role_creation_mode == "generate-iac":
            if self.iac_generator is None:
                raise RuntimeError(
                    "generate-iac mode requires an IaCGenerator to be injected"
                )
            self.iac_generator.generate(inventory, self.role_names)
            return self.iac_generator.results_for(inventory, self.role_names)

        # apply mode: build the unique set of (permission_set, account_id) pairs
        # based on actual assignments (Req 6.1, 8.1).
        ps_by_arn = {ps.arn: ps for ps in inventory.permission_sets}
        unique_pairs = sorted(
            {(a.permission_set_arn, a.account_id) for a in inventory.assignments}
        )

        results: list[RoleCreationResult] = []
        with ThreadPoolExecutor(max_workers=max(1, self.cfg.workers)) as pool:
            futures = {
                pool.submit(
                    self.create_role_for_assignment_set,
                    ps_by_arn[ps_arn],
                    account_id,
                ): (ps_arn, account_id)
                for (ps_arn, account_id) in unique_pairs
                if ps_arn in ps_by_arn
            }
            for fut in as_completed(futures):
                ps_arn, account_id = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as exc:  # noqa: BLE001
                    self.audit.log_failure(
                        "create_role",
                        f"{ps_arn}@{account_id}",
                        exc,
                    )
                    results.append(
                        RoleCreationResult(
                            permission_set_arn=ps_arn,
                            account_id=account_id,
                            role_name="",
                            role_arn=None,
                            status="FAILED",
                            error_detail=f"{type(exc).__name__}: {exc}",
                        )
                    )

        # Permission sets that were referenced in assignments but missing from the
        # inventory (e.g. inventory had errors) — surface a FAILED result.
        for (ps_arn, account_id) in unique_pairs:
            if ps_arn not in ps_by_arn:
                results.append(
                    RoleCreationResult(
                        permission_set_arn=ps_arn,
                        account_id=account_id,
                        role_name="",
                        role_arn=None,
                        status="FAILED",
                        error_detail="permission set missing from inventory",
                    )
                )

        results.sort(key=lambda r: (r.permission_set_arn, r.account_id))
        return results
