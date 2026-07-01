"""Tests for the role creator using moto-backed IAM and stubbed sessions."""

from __future__ import annotations

import io
import json
import os
from dataclasses import dataclass
from typing import Any

import boto3
import pytest

import config as cfg_mod
from audit_logger import AuditLogger
from models import (
    AccountAssignmentRecord,
    CustomerManagedPolicyReference,
    Inventory,
    PermissionSetRecord,
    RoleCreationResult,
)
from role_creator import RoleCreator

moto = pytest.importorskip("moto")
from moto import mock_aws


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


def _trust_policy(tmp_path) -> str:
    p = tmp_path / "trust.json"
    p.write_text(
        json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "account-access.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
    )
    return str(p)


def _audit():
    return AuditLogger(
        "rid-test",
        "arn:aws:iam::111111111111:role/CallerRole",
        _Cfg(),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )


def _ps(name="Admin", inline=None, managed=(), cmps=()) -> PermissionSetRecord:
    return PermissionSetRecord(
        arn=f"arn:aws:sso:::permissionSet/ssoins-x/ps-{name}",
        name=name,
        description=f"{name} permission set",
        session_duration="PT1H",
        inline_policy=inline,
        aws_managed_policy_arns=tuple(managed),
        customer_managed_policy_references=tuple(cmps),
        permission_boundary=None,
    )


def _inv(permission_sets, assignments) -> Inventory:
    return Inventory(
        hub_account_id="111111111111",
        idc_instance_arn="arn:aws:sso:::instance/ssoins-x",
        identity_store_id="d-1234567890",
        permission_sets=tuple(permission_sets),
        assignments=tuple(assignments),
        run_id="rid-test",
        captured_at="2025-01-01T00:00:00+00:00",
    )


# ─── Property 5 ───────────────────────────────────────────────────────────────

def test_property_5_role_name_template_determinism():
    """Property 5: Role name template determinism.

    Validates: Requirements 5.1, 6.2
    """
    a = cfg_mod.render_role_name("AAM-{permission_set_name}", "Admin")
    b = cfg_mod.render_role_name("AAM-{permission_set_name}", "Admin")
    assert a == b == "AAM-Admin"


# ─── Property 10: CMP ARN construction ────────────────────────────────────────

def test_property_10_cmp_arn_construction():
    """Property 10: CMP ARN construction correctness.

    Validates: Requirement 6.5
    """
    rc = RoleCreator(_Cfg(), _audit(), session_factory=lambda a: boto3.Session())
    arn = rc.cmp_arn_from_reference(
        "111122223333", CustomerManagedPolicyReference(name="MyCMP", path="/")
    )
    assert arn == "arn:aws:iam::111122223333:policy/MyCMP"

    arn2 = rc.cmp_arn_from_reference(
        "111122223333", CustomerManagedPolicyReference(name="MyCMP", path="/foo")
    )
    assert arn2 == "arn:aws:iam::111122223333:policy/foo/MyCMP"


# ─── Property 22 (role-creator slice): generate-iac makes no IAM mutation ────

def test_property_22_generate_iac_no_mutations(tmp_path):
    """Property 22 (role-creator slice): generate-iac mode performs no live IAM
    call; it delegates to the IaC generator and returns planned-role results.

    Validates: Requirement 9.4
    """
    from iac_generator import IaCGenerator

    cfg = _Cfg(role_creation_mode="generate-iac", iac_output_dir=str(tmp_path / "out"))
    inv = _inv(
        permission_sets=[_ps()],
        assignments=[
            AccountAssignmentRecord(
                permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-Admin",
                account_id="222222222222",
                principal_type="USER",
                principal_id="user-1",
                principal_display_name="Bob",
            )
        ],
    )

    def factory(_acct):
        raise RuntimeError("must not be called in generate-iac mode")

    role_names = {ps.arn: "AAM-" + ps.name for ps in inv.permission_sets}
    iac = IaCGenerator(cfg, _audit())
    rc = RoleCreator(cfg, _audit(), session_factory=factory, role_names=role_names,
                     iac_generator=iac)
    results = rc.run(inv)
    # No live mutation occurred (factory never called), and a template was written.
    assert len(results) == 1
    assert os.path.isfile(os.path.join(cfg.iac_output_dir, cfg.run_id, "roles.yaml"))


# ─── moto-backed tests for create + idempotency + tags + boundary + CMP ──────

@mock_aws
def test_property_6_one_role_per_pair_and_property_9_tags(tmp_path):
    """Property 6: One role per (permission_set, account).

    Validates: Requirement 6.1

    Also exercises Property 9: Tags applied uniformly.
    Validates: Requirement 5.3
    """
    cfg = _Cfg(
        trust_policy_path=_trust_policy(tmp_path),
        role_tags={"Owner": "Platform", "Team": "Identity"},
    )
    spoke_session = boto3.Session(region_name="us-east-1")
    # moto scopes IAM to a single (default) account regardless of the assignment
    # account_id, so the session_factory always returns this one session. Use
    # distinct permission sets to exercise multiple unique pairs without role
    # name collisions within the same moto account.
    inv = _inv(
        permission_sets=[_ps("Admin"), _ps("ReadOnly"), _ps("Billing")],
        assignments=[
            AccountAssignmentRecord(
                permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-Admin",
                account_id="222222222222",
                principal_type="USER",
                principal_id="u1",
                principal_display_name="Bob",
            ),
            AccountAssignmentRecord(
                permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-ReadOnly",
                account_id="222222222222",
                principal_type="GROUP",
                principal_id="g1",
                principal_display_name="Eng",
            ),
            AccountAssignmentRecord(
                permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-Billing",
                account_id="222222222222",
                principal_type="USER",
                principal_id="u2",
                principal_display_name="Alice",
            ),
        ],
    )

    rc = RoleCreator(
        cfg,
        _audit(),
        session_factory=lambda _acct: spoke_session,
        role_names={ps.arn: "AAM-" + ps.name for ps in inv.permission_sets},
    )
    results = rc.run(inv)

    # 3 unique (ps_arn, account_id) pairs
    assert len(results) == 3
    assert {(r.permission_set_arn, r.account_id) for r in results} == {
        ("arn:aws:sso:::permissionSet/ssoins-x/ps-Admin", "222222222222"),
        ("arn:aws:sso:::permissionSet/ssoins-x/ps-ReadOnly", "222222222222"),
        ("arn:aws:sso:::permissionSet/ssoins-x/ps-Billing", "222222222222"),
    }
    assert all(r.status == "CREATED" for r in results)

    # Verify tags
    iam = spoke_session.client("iam")
    role = iam.get_role(RoleName="AAM-Admin")["Role"]
    tags = {t["Key"]: t["Value"] for t in role.get("Tags", [])}
    assert tags == {"Owner": "Platform", "Team": "Identity"}


@mock_aws
def test_property_8_permission_boundary_applied(tmp_path):
    """Property 8: Permission boundary applied when configured.

    Validates: Requirements 5.6, 6.7
    """
    spoke_session = boto3.Session(region_name="us-east-1")

    # Create a managed policy in moto to use as a boundary.
    iam = spoke_session.client("iam")
    iam.create_policy(
        PolicyName="MyBoundary",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ),
    )
    # Look up the actual ARN moto produced.
    pol_arn = iam.list_policies(Scope="Local")["Policies"][0]["Arn"]

    cfg = _Cfg(
        trust_policy_path=_trust_policy(tmp_path),
        permission_boundary_arn=pol_arn,
    )

    inv = _inv(
        permission_sets=[_ps("Admin")],
        assignments=[
            AccountAssignmentRecord(
                permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-Admin",
                account_id="222222222222",
                principal_type="USER",
                principal_id="u1",
                principal_display_name="Bob",
            )
        ],
    )
    rc = RoleCreator(
        cfg,
        _audit(),
        session_factory=lambda _: spoke_session,
        role_names={ps.arn: "AAM-" + ps.name for ps in inv.permission_sets},
    )
    results = rc.run(inv)
    assert results[0].status == "CREATED"
    assert results[0].permission_boundary_arn == pol_arn

    role = iam.get_role(RoleName="AAM-Admin")["Role"]
    assert role["PermissionsBoundary"]["PermissionsBoundaryArn"] == pol_arn


@mock_aws
def test_property_11_missing_cmp_fail_and_continue(tmp_path):
    """Property 11: Missing CMP fail-and-continue.

    Validates: Requirement 6.6
    """
    spoke_session = boto3.Session(region_name="us-east-1")
    iam = spoke_session.client("iam")

    # Pre-create one CMP that exists; the other won't.
    iam.create_policy(
        PolicyName="ExistingCMP",
        Path="/aam/",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]}
        ),
    )

    cfg = _Cfg(trust_policy_path=_trust_policy(tmp_path))

    # Use the moto account id the IAM session is actually scoped to so the
    # computed CMP ARN (account + path + name) matches the pre-created policy.
    acct_id = spoke_session.client("sts").get_caller_identity()["Account"]

    ps = _ps(
        "Admin",
        cmps=[
            CustomerManagedPolicyReference(name="ExistingCMP", path="/aam/"),
            CustomerManagedPolicyReference(name="MissingCMP", path="/aam/"),
        ],
    )
    inv = _inv(
        permission_sets=[ps],
        assignments=[
            AccountAssignmentRecord(
                permission_set_arn=ps.arn,
                account_id=acct_id,
                principal_type="USER",
                principal_id="u1",
                principal_display_name="Bob",
            )
        ],
    )

    rc = RoleCreator(cfg, _audit(), session_factory=lambda _: spoke_session, role_names={ps.arn: "AAM-" + ps.name})
    results = rc.run(inv)
    assert results[0].status == "CREATED"
    # Only one CMP should be attached.
    assert len(results[0].attached_cmp_arns) == 1
    assert "ExistingCMP" in results[0].attached_cmp_arns[0]


@mock_aws
def test_property_12_idempotent_role_recreation(tmp_path):
    """Property 12: Idempotent role re-creation.

    Validates: Requirements 6.8, 11.1
    """
    spoke_session = boto3.Session(region_name="us-east-1")
    iam = spoke_session.client("iam")

    # Pre-create the role with the same name.
    iam.create_role(
        RoleName="AAM-Admin",
        Path="/aam/",
        AssumeRolePolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        ),
    )

    cfg = _Cfg(trust_policy_path=_trust_policy(tmp_path))
    inv = _inv(
        permission_sets=[_ps("Admin")],
        assignments=[
            AccountAssignmentRecord(
                permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-Admin",
                account_id="222222222222",
                principal_type="USER",
                principal_id="u1",
                principal_display_name="Bob",
            )
        ],
    )

    rc = RoleCreator(
        cfg,
        _audit(),
        session_factory=lambda _: spoke_session,
        role_names={ps.arn: "AAM-" + ps.name for ps in inv.permission_sets},
    )
    results = rc.run(inv)
    assert len(results) == 1
    assert results[0].status == "EXISTING"


@mock_aws
def test_inline_to_cmp_conversion(tmp_path):
    """Unit test: inline-to-CMP conversion creates and attaches the CMP.

    Validates: Requirement 5.7
    """
    spoke_session = boto3.Session(region_name="us-east-1")

    cfg = _Cfg(
        trust_policy_path=_trust_policy(tmp_path),
        convert_inline_to_cmp=True,
    )
    ps = _ps(
        "Admin",
        inline={"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    )
    inv = _inv(
        permission_sets=[ps],
        assignments=[
            AccountAssignmentRecord(
                permission_set_arn=ps.arn,
                account_id="222222222222",
                principal_type="USER",
                principal_id="u1",
                principal_display_name="Bob",
            )
        ],
    )

    rc = RoleCreator(
        cfg,
        _audit(),
        session_factory=lambda _: spoke_session,
        role_names={ps.arn: "AAM-" + ps.name},
    )
    results = rc.run(inv)
    assert results[0].status == "CREATED"
    assert results[0].converted_cmp_arn is not None
    assert "AAM-Admin-inline" in results[0].converted_cmp_arn

    iam = spoke_session.client("iam")
    # CMP exists with the right name.
    pols = iam.list_policies(Scope="Local")["Policies"]
    names = [p["PolicyName"] for p in pols]
    assert "AAM-Admin-inline" in names
    # No inline policy embedded on the role.
    inline_names = iam.list_role_policies(RoleName="AAM-Admin")["PolicyNames"]
    assert inline_names == []
