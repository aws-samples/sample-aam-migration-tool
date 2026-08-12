"""Entitlement creator: AAM application + entitlements per IdC assignment."""

from __future__ import annotations

import uuid
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from audit_logger import AuditLogger
from aws_session import HubContext, boto_config
from config import Config
from models import (
    AccountAssignmentRecord,
    ApplicationResult,
    EntitlementCreationResult,
    Inventory,
    RoleCreationResult,
)


_CONFLICT_CODES = {
    "ConflictException",
    "ResourceAlreadyExistsException",
    "EntityAlreadyExistsException",
}

_NOT_FOUND_CODES = {
    "ResourceNotFoundException",
    "NotFoundException",
    "NoSuchEntityException",
}


class EntitlementCreator:
    """Creates per-assignment entitlements against an operator-supplied AAM
    application.

    The AAM application is an operator-managed prerequisite (Req 10). This
    component never calls CreateApplication; it references the ARN supplied via
    ``--aam-application-arn`` and optionally validates it via GetApplication.

    The AAM service is invoked by boto3 client name `account-access`. Tests can
    inject a stubbed client via the `aam_client` constructor parameter.
    """

    def __init__(
        self,
        hub: HubContext,
        cfg: Config,
        audit: AuditLogger,
        aam_client: Any | None = None,
    ) -> None:
        self.hub = hub
        self.cfg = cfg
        self.audit = audit
        if aam_client is None:
            client_kwargs = {
                "region_name": getattr(cfg, "aam_region", None) or cfg.region,
                "config": boto_config(cfg.workers),
            }
            aam_client = hub.session.client("account-access", **client_kwargs)
        self.aam = aam_client

    # ── Application (Req 10 — operator-supplied prerequisite) ─────────────────

    def resolve_application(self, idc_instance_arn: str) -> ApplicationResult:
        """Resolve the operator-supplied AAM application ARN. Never creates it
        (Req 10.4, 10.7). When validation is enabled, verify via GetApplication
        (Req 10.5) and fail on not-found (Req 10.6)."""
        app_arn = self.cfg.aam_application_arn

        if self.cfg.role_creation_mode != "apply":
            # generate-iac (or any non-apply mode): the entitlements are emitted
            # into the CloudFormation template, not created live. Return a
            # planned result without calling AAM.
            self.audit.log_success(
                "plan_use_application",
                app_arn or "(none supplied)",
                idc_instance_arn=idc_instance_arn,
            )
            return ApplicationResult(
                application_arn=app_arn,
                status="SKIPPED",
                idc_instance_arn=idc_instance_arn,
                error_detail="generate-iac",
            )

        if not app_arn:
            # config.validate already enforces this in apply mode; guard anyway.
            self.audit.log(
                "use_application",
                "(none supplied)",
                "FAILURE",
                error_detail="no --aam-application-arn supplied",
            )
            return ApplicationResult(
                application_arn=None,
                status="FAILED",
                idc_instance_arn=idc_instance_arn,
                error_detail="no --aam-application-arn supplied",
            )

        if not self.cfg.validate_aam_application:
            self.audit.log_success("use_application", app_arn)
            return ApplicationResult(
                application_arn=app_arn,
                status="SUPPLIED",
                idc_instance_arn=idc_instance_arn,
            )

        # Validate existence via GetApplication (Req 10.5, 10.6).
        try:
            self.aam.get_application(applicationArn=app_arn)
            self.audit.log_success("validate_application", app_arn)
            return ApplicationResult(
                application_arn=app_arn,
                status="VALIDATED",
                idc_instance_arn=idc_instance_arn,
                validated=True,
            )
        except (ClientError, BotoCoreError) as exc:  # noqa: BLE001
            self.audit.log_failure("validate_application", app_arn, exc)
            return ApplicationResult(
                application_arn=app_arn,
                status="FAILED",
                idc_instance_arn=idc_instance_arn,
                error_detail=f"{type(exc).__name__}: {exc}",
            )

    # ── Entitlements (Req 8) ─────────────────────────────────────────────────

    def existing_entitlement_id(
        self,
        application_arn: str,
        principal_type: str,
        principal_id: str,
        role_arn: str,
    ) -> str | None:
        # ListEntitlements requires a filter; narrow by principal + role so the
        # probe returns only the entitlement we care about.
        key = "userId" if principal_type == "USER" else "groupId"
        filter_block: dict[str, Any] = {
            "principalRole": {
                "principal": {"identityCenter": {key: principal_id}},
                "roleArn": role_arn,
            }
        }
        try:
            next_token: str | None = None
            while True:
                kwargs: dict[str, Any] = {
                    "applicationArn": application_arn,
                    "filter": filter_block,
                    "maxResults": 50,
                }
                if next_token:
                    kwargs["nextToken"] = next_token
                resp = self.aam.list_entitlements(**kwargs)
                for ent in resp.get("entitlements", []):
                    pr = ent.get("entitlement", {}).get("principalRole", {})
                    pr_principal = pr.get("principal", {}).get("identityCenter", {})
                    pr_role = pr.get("roleArn")
                    if pr_role != role_arn:
                        continue
                    if pr_principal.get("userId") == principal_id or pr_principal.get("groupId") == principal_id:
                        return ent.get("entitlementId")
                next_token = resp.get("nextToken")
                if not next_token:
                    break
        except (ClientError, BotoCoreError) as exc:  # noqa: BLE001
            self.audit.log_failure(
                "list_entitlements",
                f"{application_arn}#{principal_id}#{role_arn}",
                exc,
            )
        return None

    def create_entitlement_for_assignment(
        self,
        application_arn: str,
        idc_instance_arn: str,
        assignment: AccountAssignmentRecord,
        role_result: RoleCreationResult,
    ) -> EntitlementCreationResult:
        if role_result.status == "FAILED" or not role_result.role_arn:
            self.audit.log(
                "skip_entitlement_role_failed",
                f"{assignment.permission_set_arn}@{assignment.account_id}#{assignment.principal_id}",
                "FAILURE",
                error_detail=f"role_creation_failed: {role_result.error_detail or role_result.status}",
            )
            return EntitlementCreationResult(
                application_arn=application_arn,
                permission_set_arn=assignment.permission_set_arn,
                account_id=assignment.account_id,
                principal_type=assignment.principal_type,
                principal_id=assignment.principal_id,
                role_arn=None,
                entitlement_id=None,
                status="SKIPPED",
                error_detail=f"role_creation_failed: {role_result.error_detail or role_result.status}",
            )

        if self.cfg.role_creation_mode != "apply":
            self.audit.log_success(
                "plan_create_entitlement",
                role_result.role_arn,
                principal_type=assignment.principal_type,
                principal_id=assignment.principal_id,
            )
            return EntitlementCreationResult(
                application_arn=application_arn,
                permission_set_arn=assignment.permission_set_arn,
                account_id=assignment.account_id,
                principal_type=assignment.principal_type,
                principal_id=assignment.principal_id,
                role_arn=role_result.role_arn,
                entitlement_id=None,
                status="SKIPPED",
                error_detail="generate-iac",
            )

        # Idempotency check (Req 8.5, 11.3)
        existing_id = self.existing_entitlement_id(
            application_arn, assignment.principal_type, assignment.principal_id, role_result.role_arn
        )
        if existing_id:
            self.audit.log_success(
                "entitlement_already_exists",
                existing_id,
                role_arn=role_result.role_arn,
            )
            return EntitlementCreationResult(
                application_arn=application_arn,
                permission_set_arn=assignment.permission_set_arn,
                account_id=assignment.account_id,
                principal_type=assignment.principal_type,
                principal_id=assignment.principal_id,
                role_arn=role_result.role_arn,
                entitlement_id=existing_id,
                status="EXISTING",
            )

        # identityCenter is a tagged union: exactly one of userId / groupId.
        principal_block: dict[str, Any] = {}
        if assignment.principal_type == "USER":
            principal_block["userId"] = assignment.principal_id
        else:
            principal_block["groupId"] = assignment.principal_id

        try:
            # Retry on ValidationException — IAM role may not have propagated yet
            import time as _time
            max_retries = 3
            resp = None
            for attempt in range(max_retries):
                try:
                    resp = self.aam.create_entitlement(
                        applicationArn=application_arn,
                        entitlement={
                            "principalRole": {
                                "principal": {"identityCenter": principal_block},
                                "roleArn": role_result.role_arn,
                            }
                        },
                    )
                    break
                except ClientError as retry_exc:
                    code = retry_exc.response.get("Error", {}).get("Code", "")
                    if code == "ValidationException" and attempt < max_retries - 1:
                        _time.sleep(3 * (attempt + 1))
                    else:
                        raise

            ent_id = resp["entitlementId"]
            self.audit.log_success(
                "create_entitlement",
                ent_id,
                role_arn=role_result.role_arn,
                principal_type=assignment.principal_type,
                principal_id=assignment.principal_id,
            )
            return EntitlementCreationResult(
                application_arn=application_arn,
                permission_set_arn=assignment.permission_set_arn,
                account_id=assignment.account_id,
                principal_type=assignment.principal_type,
                principal_id=assignment.principal_id,
                role_arn=role_result.role_arn,
                entitlement_id=ent_id,
                status="CREATED",
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _CONFLICT_CODES:
                existing_id = self.existing_entitlement_id(
                    application_arn, assignment.principal_type, assignment.principal_id, role_result.role_arn
                )
                if existing_id:
                    self.audit.log_success(
                        "entitlement_already_exists_post_create",
                        existing_id,
                    )
                    return EntitlementCreationResult(
                        application_arn=application_arn,
                        permission_set_arn=assignment.permission_set_arn,
                        account_id=assignment.account_id,
                        principal_type=assignment.principal_type,
                        principal_id=assignment.principal_id,
                        role_arn=role_result.role_arn,
                        entitlement_id=existing_id,
                        status="EXISTING",
                    )
            self.audit.log_failure(
                "create_entitlement",
                f"{assignment.principal_id}->{role_result.role_arn}",
                exc,
            )
            return EntitlementCreationResult(
                application_arn=application_arn,
                permission_set_arn=assignment.permission_set_arn,
                account_id=assignment.account_id,
                principal_type=assignment.principal_type,
                principal_id=assignment.principal_id,
                role_arn=role_result.role_arn,
                entitlement_id=None,
                status="FAILED",
                error_detail=f"{type(exc).__name__}: {exc}",
            )

    # ── Orchestration ────────────────────────────────────────────────────────

    def run(
        self,
        inventory: Inventory,
        role_results: list[RoleCreationResult],
    ) -> tuple[ApplicationResult, list[EntitlementCreationResult]]:
        application = self.resolve_application(inventory.idc_instance_arn)

        if application.status == "FAILED":
            # No usable application means no entitlements; surface skipped entries.
            return application, [
                EntitlementCreationResult(
                    application_arn=application.application_arn or "",
                    permission_set_arn=a.permission_set_arn,
                    account_id=a.account_id,
                    principal_type=a.principal_type,
                    principal_id=a.principal_id,
                    role_arn=None,
                    entitlement_id=None,
                    status="SKIPPED",
                    error_detail="application_unavailable",
                )
                for a in inventory.assignments
            ]

        if application.status == "SKIPPED":
            # generate-iac — emit planned entitlements (they live in the template).
            return application, [
                self.create_entitlement_for_assignment(
                    application_arn=application.application_arn or "",
                    idc_instance_arn=inventory.idc_instance_arn,
                    assignment=a,
                    role_result=self._role_result_for(a, role_results),
                )
                for a in inventory.assignments
            ]

        role_lookup: dict[tuple[str, str], RoleCreationResult] = {
            (r.permission_set_arn, r.account_id): r for r in role_results
        }
        results: list[EntitlementCreationResult] = []
        for a in inventory.assignments:
            role = role_lookup.get(
                (a.permission_set_arn, a.account_id),
                RoleCreationResult(
                    permission_set_arn=a.permission_set_arn,
                    account_id=a.account_id,
                    role_name="",
                    role_arn=None,
                    status="FAILED",
                    error_detail="role result missing",
                ),
            )
            results.append(
                self.create_entitlement_for_assignment(
                    application_arn=application.application_arn or "",
                    idc_instance_arn=inventory.idc_instance_arn,
                    assignment=a,
                    role_result=role,
                )
            )
        return application, results

    @staticmethod
    def _role_result_for(
        assignment: AccountAssignmentRecord,
        role_results: list[RoleCreationResult],
    ) -> RoleCreationResult:
        for r in role_results:
            if r.permission_set_arn == assignment.permission_set_arn and r.account_id == assignment.account_id:
                return r
        return RoleCreationResult(
            permission_set_arn=assignment.permission_set_arn,
            account_id=assignment.account_id,
            role_name="",
            role_arn=None,
            status="FAILED",
            error_detail="role result missing",
        )
