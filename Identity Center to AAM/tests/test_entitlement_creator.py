"""Tests for the entitlement creator using a stubbed AAM client."""

from __future__ import annotations

import io
import uuid
from dataclasses import dataclass

import pytest
from botocore.exceptions import ClientError

from audit_logger import AuditLogger
from aws_session import HubContext
from entitlement_creator import EntitlementCreator
from models import (
    AccountAssignmentRecord,
    Inventory,
    PermissionSetRecord,
    RoleCreationResult,
)


# ─── Test scaffolding ─────────────────────────────────────────────────────────

@dataclass
class _Cfg:
    account_scope: str = "single"
    account_ids: tuple = ()
    role_name: str | None = None
    auto_approve: bool = True
    role_creation_mode: str = "apply"
    role_name_template: str = "AAM-{permission_set_name}"
    role_path: str = "/aam/"
    role_tags: dict | None = None
    trust_policy_path: str | None = None
    permission_boundary_arn: str | None = None
    convert_inline_to_cmp: bool = False
    cmp_name_template: str = "AAM-{permission_set_name}-inline"
    plan_path: str | None = None
    plan_output_path: str | None = None
    iac_output_dir: str = "output"
    aam_application_arn: str | None = "arn:aws:accountaccess:us-east-1:111111111111:application/app-test"
    validate_aam_application: bool = False
    aam_idc_instance_arn: str | None = None
    audit_to_cloudwatch: bool = False
    cloudwatch_log_group: str | None = None
    audit_to_file: bool = False
    audit_file_path: str | None = None
    inventory_output_path: str | None = None
    mapping_output_format: str = "JSON"
    mapping_output_path: str | None = None
    workers: int = 2
    run_id: str = "rid-test"
    out_of_scope_request: str | None = None
    region: str = "us-east-1"

    def __post_init__(self):
        if self.role_tags is None:
            self.role_tags = {}


class _FakeAAM:
    """In-memory AAM stub matching the get_application + create_entitlement +
    list_entitlements surface used by EntitlementCreator.

    The tool never creates the AAM application (Req 10), so this stub
    deliberately has no create_application/list_applications. ``get_application``
    is used only when ``--validate-aam-application`` is set.
    """

    def __init__(self):
        self.applications: dict[str, dict] = {}
        self.entitlements: list[dict] = []
        self.get_application_calls = 0
        self.created_entitlement_calls = 0

    def get_application(self, **kwargs):
        self.get_application_calls += 1
        arn = kwargs["applicationArn"]
        if arn not in self.applications:
            err = {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}}
            raise ClientError(err, "GetApplication")
        return {"application": self.applications[arn]}

    def create_entitlement(self, **kwargs):
        self.created_entitlement_calls += 1
        app_arn = kwargs["applicationArn"]
        ent = kwargs["entitlement"]
        principal = ent["principalRole"]["principal"]["identityCenter"]
        principal_id = principal.get("userId") or principal.get("groupId")
        role_arn = ent["principalRole"]["roleArn"]
        for e in self.entitlements:
            if (
                e["applicationArn"] == app_arn
                and e["principal_id"] == principal_id
                and e["roleArn"] == role_arn
            ):
                err = {"Error": {"Code": "ConflictException", "Message": "exists"}}
                raise ClientError(err, "CreateEntitlement")
        ent_id = f"ent-{uuid.uuid4().hex[:12]}"
        self.entitlements.append(
            {
                "entitlementId": ent_id,
                "applicationArn": app_arn,
                "principal_id": principal_id,
                "roleArn": role_arn,
                "entitlement": ent,
            }
        )
        return {"entitlementId": ent_id}

    def list_entitlements(self, **kwargs):
        app_arn = kwargs["applicationArn"]
        # Mirror the real API: filter is a required parameter.
        filt = kwargs["filter"]
        pr_filter = filt.get("principalRole", {})
        want_role = pr_filter.get("roleArn")
        want_ic = pr_filter.get("principal", {}).get("identityCenter", {})
        want_principal = want_ic.get("userId") or want_ic.get("groupId")
        out = []
        for e in self.entitlements:
            if e["applicationArn"] != app_arn:
                continue
            if want_role is not None and e["roleArn"] != want_role:
                continue
            if want_principal is not None and e["principal_id"] != want_principal:
                continue
            out.append({"entitlementId": e["entitlementId"], "entitlement": e["entitlement"]})
        return {"entitlements": out}


def _audit():
    return AuditLogger("rid", "arn:aws:iam::1:role/r", _Cfg(), stdout=io.StringIO(), stderr=io.StringIO())


def _hub():
    import boto3

    return HubContext(
        session=boto3.Session(region_name="us-east-1"),
        account_id="111111111111",
        caller_arn="arn:aws:iam::111111111111:role/Caller",
        region="us-east-1",
    )


def _inv(assignments=()) -> Inventory:
    return Inventory(
        hub_account_id="111111111111",
        idc_instance_arn="arn:aws:sso:::instance/ssoins-x",
        identity_store_id="d-x",
        permission_sets=(
            PermissionSetRecord(
                arn="arn:aws:sso:::permissionSet/ssoins-x/ps-1",
                name="Admin",
                description="",
                session_duration="PT1H",
                inline_policy=None,
                aws_managed_policy_arns=(),
                customer_managed_policy_references=(),
                permission_boundary=None,
            ),
        ),
        assignments=tuple(assignments),
        run_id="rid",
        captured_at="2025-01-01T00:00:00+00:00",
    )


# ─── Property 13: operator-supplied application resolution ────────────────────

def test_property_13_supplied_application_resolution():
    """Property 13: Operator-supplied application is referenced, never created.

    Validates: Requirements 10.4, 10.7
    """
    aam = _FakeAAM()
    app_arn = "arn:aws:accountaccess:us-east-1:111111111111:application/app-test"

    # No validation: the supplied arn is returned as SUPPLIED with no AAM calls.
    ec = EntitlementCreator(_hub(), _Cfg(), _audit(), aam_client=aam)
    result = ec.resolve_application("arn:aws:sso:::instance/ssoins-x")
    assert result.status == "SUPPLIED"
    assert result.application_arn == app_arn
    assert result.validated is False
    assert aam.get_application_calls == 0
    assert not hasattr(aam, "create_application")

    # Validation enabled + application present: status VALIDATED.
    aam_present = _FakeAAM()
    aam_present.applications[app_arn] = {"applicationArn": app_arn}
    ec_present = EntitlementCreator(
        _hub(), _Cfg(validate_aam_application=True), _audit(), aam_client=aam_present
    )
    present = ec_present.resolve_application("arn:aws:sso:::instance/ssoins-x")
    assert present.status == "VALIDATED"
    assert present.validated is True
    assert present.application_arn == app_arn
    assert aam_present.get_application_calls == 1

    # Validation enabled + application missing: status FAILED.
    aam_missing = _FakeAAM()
    ec_missing = EntitlementCreator(
        _hub(), _Cfg(validate_aam_application=True), _audit(), aam_client=aam_missing
    )
    missing = ec_missing.resolve_application("arn:aws:sso:::instance/ssoins-x")
    assert missing.status == "FAILED"
    assert aam_missing.get_application_calls == 1


# ─── Property 14: idempotent entitlement reuse ────────────────────────────────

def test_property_14_idempotent_entitlement_reuse():
    """Property 14: Idempotent entitlement reuse.

    Validates: Requirements 8.5, 11.3
    """
    aam = _FakeAAM()
    a = AccountAssignmentRecord(
        permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-1",
        account_id="222222222222",
        principal_type="USER",
        principal_id="user-1",
        principal_display_name="Bob",
    )
    role_arn = "arn:aws:iam::222222222222:role/aam/AAM-Admin"
    inv = _inv([a])
    role = RoleCreationResult(
        permission_set_arn=a.permission_set_arn,
        account_id=a.account_id,
        role_name="AAM-Admin",
        role_arn=role_arn,
        status="CREATED",
    )

    ec = EntitlementCreator(_hub(), _Cfg(), _audit(), aam_client=aam)
    app, results = ec.run(inv, [role])
    assert results[0].status == "CREATED"

    # Second run with the same inputs must reuse.
    ec2 = EntitlementCreator(_hub(), _Cfg(), _audit(), aam_client=aam)
    app2, results2 = ec2.run(inv, [role])
    assert results2[0].status == "EXISTING"
    assert aam.created_entitlement_calls == 1  # Only the first call


# ─── Property 15: skip when role failed ───────────────────────────────────────

def test_property_15_skip_when_role_failed():
    """Property 15: Entitlement skip when role failed.

    Validates: Requirement 8.4
    """
    aam = _FakeAAM()
    a = AccountAssignmentRecord(
        permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-1",
        account_id="222222222222",
        principal_type="GROUP",
        principal_id="g-1",
        principal_display_name="Eng",
    )
    inv = _inv([a])
    role = RoleCreationResult(
        permission_set_arn=a.permission_set_arn,
        account_id=a.account_id,
        role_name="AAM-Admin",
        role_arn=None,
        status="FAILED",
        error_detail="boom",
    )

    ec = EntitlementCreator(_hub(), _Cfg(), _audit(), aam_client=aam)
    app, results = ec.run(inv, [role])
    assert results[0].status == "SKIPPED"
    assert results[0].entitlement_id is None
    assert aam.created_entitlement_calls == 0


# ─── USER vs GROUP request shape ──────────────────────────────────────────────

def test_user_vs_group_request_shape():
    """Validates Req 8.2, 8.3."""
    aam = _FakeAAM()
    a_user = AccountAssignmentRecord(
        permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-1",
        account_id="222222222222",
        principal_type="USER",
        principal_id="user-1",
        principal_display_name="Bob",
    )
    a_group = AccountAssignmentRecord(
        permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-1",
        account_id="222222222222",
        principal_type="GROUP",
        principal_id="g-1",
        principal_display_name="Eng",
    )
    inv = _inv([a_user, a_group])
    role = RoleCreationResult(
        permission_set_arn=a_user.permission_set_arn,
        account_id=a_user.account_id,
        role_name="AAM-Admin",
        role_arn="arn:aws:iam::222222222222:role/aam/AAM-Admin",
        status="CREATED",
    )

    ec = EntitlementCreator(_hub(), _Cfg(), _audit(), aam_client=aam)
    app, results = ec.run(inv, [role])
    assert all(r.status == "CREATED" for r in results)

    # Verify request shape stored.
    user_req = next(e for e in aam.entitlements if e["principal_id"] == "user-1")["entitlement"]
    group_req = next(e for e in aam.entitlements if e["principal_id"] == "g-1")["entitlement"]
    assert "userId" in user_req["principalRole"]["principal"]["identityCenter"]
    assert "groupId" in group_req["principalRole"]["principal"]["identityCenter"]


def test_application_failure_propagates_to_entitlements():
    """When application validation fails, every entitlement is SKIPPED.

    Validates: Requirement 10.6
    """

    class _FailingAAM(_FakeAAM):
        def get_application(self, **kwargs):
            self.get_application_calls += 1
            err = {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}
            raise ClientError(err, "GetApplication")

    aam = _FailingAAM()
    a = AccountAssignmentRecord(
        permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-1",
        account_id="222222222222",
        principal_type="USER",
        principal_id="user-1",
        principal_display_name="Bob",
    )
    inv = _inv([a])
    role = RoleCreationResult(
        permission_set_arn=a.permission_set_arn,
        account_id=a.account_id,
        role_name="AAM-Admin",
        role_arn="arn:aws:iam::222222222222:role/aam/AAM-Admin",
        status="CREATED",
    )

    cfg = _Cfg(validate_aam_application=True)
    ec = EntitlementCreator(_hub(), cfg, _audit(), aam_client=aam)
    app, results = ec.run(inv, [role])
    assert app.status == "FAILED"
    assert results[0].status == "SKIPPED"
    assert aam.created_entitlement_calls == 0


def test_generate_iac_creates_no_application_or_entitlement():
    """Property 22 (entitlement-creator slice): in generate-iac mode the
    entitlements live in the CloudFormation template, so no AAM API is called."""
    aam = _FakeAAM()
    a = AccountAssignmentRecord(
        permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-1",
        account_id="222222222222",
        principal_type="USER",
        principal_id="user-1",
        principal_display_name="Bob",
    )
    inv = _inv([a])
    role = RoleCreationResult(
        permission_set_arn=a.permission_set_arn,
        account_id=a.account_id,
        role_name="AAM-Admin",
        role_arn="arn:aws:iam::222222222222:role/aam/AAM-Admin",
        status="CREATED",
        error_detail="generated-iac",
    )
    cfg = _Cfg(role_creation_mode="generate-iac")
    ec = EntitlementCreator(_hub(), cfg, _audit(), aam_client=aam)
    app, results = ec.run(inv, [role])
    assert app.status == "SKIPPED"
    assert all(r.status == "SKIPPED" for r in results)
    assert aam.get_application_calls == 0
    assert aam.created_entitlement_calls == 0
