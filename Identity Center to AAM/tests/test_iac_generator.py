"""Tests for the IaC generator (iac_generator.py)."""

from __future__ import annotations

import io
import os
from dataclasses import dataclass, field

from hypothesis import given, settings
from hypothesis import strategies as st

from audit_logger import AuditLogger
from iac_generator import (
    AAM_TRUST_ACTIONS,
    AAM_TRUST_SERVICE_PRINCIPAL,
    IaCGenerator,
)
from models import AccountAssignmentRecord, Inventory, PermissionSetRecord


_APP_ARN = "arn:aws:accountaccess:us-east-1:111111111111:application/app-1"


@dataclass
class _Cfg:
    role_path: str = "/aam/"
    role_tags: dict = field(default_factory=dict)
    trust_policy_path: str | None = None
    permission_boundary_arn: str | None = None
    iac_output_dir: str = "output"
    aam_application_arn: str | None = _APP_ARN
    run_id: str = "rid-test"
    audit_to_cloudwatch: bool = False
    cloudwatch_log_group: str | None = None
    audit_to_file: bool = False
    audit_file_path: str | None = None
    region: str = "us-east-1"
    workers: int = 2


def _audit():
    return AuditLogger(
        "rid-test",
        "arn:aws:iam::111111111111:role/Caller",
        _Cfg(),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )


def _ps(name, inline=None, managed=(), cmps=()) -> PermissionSetRecord:
    return PermissionSetRecord(
        arn=f"arn:aws:sso:::permissionSet/ssoins-x/ps-{name}",
        name=name,
        description="",
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


def _roles(cfn) -> dict:
    return {
        k: v for k, v in cfn["Resources"].items() if v["Type"] == "AWS::IAM::Role"
    }


def _entitlements(cfn) -> dict:
    return {
        k: v
        for k, v in cfn["Resources"].items()
        if v["Type"] == "AWS::AccountAccess::Entitlement"
    }


# ─── Property 18: generate-iac writes the CloudFormation template ─────────────

def test_property_18_generate_writes_template(tmp_path):
    """Property 18: generate-iac writes roles.yaml (no live mutation).

    Validates: Requirements 7.5, 9.1, 9.7
    """
    cfg = _Cfg(iac_output_dir=str(tmp_path))
    gen = IaCGenerator(cfg, _audit())
    ps = _ps("Admin", managed=["arn:aws:iam::aws:policy/AdministratorAccess"])
    inv = _inv([ps], [
        AccountAssignmentRecord(
            permission_set_arn=ps.arn, account_id="222222222222",
            principal_type="USER", principal_id="u1", principal_display_name="Omar",
        )
    ])

    yaml_path = gen.generate(inv, {ps.arn: "AAM-Admin"})
    assert os.path.isfile(yaml_path)
    assert yaml_path.endswith(f"{inv.run_id}/roles.yaml")
    # No Terraform artifact is produced.
    assert not os.path.exists(os.path.join(os.path.dirname(yaml_path), "roles.tf"))


# ─── Property 20: IaC role fidelity (trust principal + policies) ──────────────

@settings(max_examples=100, deadline=None)
@given(
    name=st.text(min_size=1, max_size=12, alphabet="ABCDEFGHIJKLMNOPabcdef0123456789"),
    managed=st.lists(
        st.text(min_size=1, max_size=12, alphabet="ABCDEFabc").map(
            lambda n: f"arn:aws:iam::aws:policy/{n}"
        ),
        max_size=3,
        unique=True,
    ),
    has_inline=st.booleans(),
)
def test_property_20_iac_role_fidelity(tmp_path_factory, name, managed, has_inline):
    """Property 20: IaC role fidelity — AAM trust principal + permission-set policies.

    Validates: Requirements 9.3, 9.4, 9.6
    """
    import yaml as yaml_mod

    tmp_path = tmp_path_factory.mktemp("iac")
    inline = (
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]}
        if has_inline else None
    )
    cfg = _Cfg(iac_output_dir=str(tmp_path))
    gen = IaCGenerator(cfg, _audit())
    ps = _ps(name, inline=inline, managed=managed)
    role_name = f"AAM-{name}"
    inv = _inv([ps], [
        AccountAssignmentRecord(
            permission_set_arn=ps.arn, account_id="222222222222",
            principal_type="USER", principal_id="u1", principal_display_name="x",
        )
    ])
    yaml_path = gen.generate(inv, {ps.arn: role_name})

    with open(yaml_path) as f:
        cfn = yaml_mod.safe_load(f)
    roles = _roles(cfn)
    assert len(roles) == 1
    role = next(iter(roles.values()))
    props = role["Properties"]
    assert props["RoleName"] == role_name
    stmt = props["AssumeRolePolicyDocument"]["Statement"][0]
    assert stmt["Principal"]["Service"] == AAM_TRUST_SERVICE_PRINCIPAL
    assert set(stmt["Action"]) == set(AAM_TRUST_ACTIONS)
    for arn in managed:
        assert arn in props.get("ManagedPolicyArns", [])
    if has_inline:
        assert props["Policies"][0]["PolicyDocument"] == inline
    else:
        assert "Policies" not in props


# ─── Entitlement resources are emitted and wired to roles via Fn::GetAtt ──────

def test_entitlement_resources_emitted(tmp_path):
    """Entitlements emitted as AWS::AccountAccess::Entitlement, wired to the role.

    Validates: Requirements 11.1, 11.2 (IaC form)
    """
    import yaml as yaml_mod

    cfg = _Cfg(iac_output_dir=str(tmp_path))
    gen = IaCGenerator(cfg, _audit())
    ps = _ps("Admin")
    inv = _inv([ps], [
        AccountAssignmentRecord(
            permission_set_arn=ps.arn, account_id="222222222222",
            principal_type="USER", principal_id="11111111-1111-1111-1111-111111111111",
            principal_display_name="Omar",
        ),
        AccountAssignmentRecord(
            permission_set_arn=ps.arn, account_id="222222222222",
            principal_type="GROUP", principal_id="22222222-2222-2222-2222-222222222222",
            principal_display_name="Eng",
        ),
    ])
    yaml_path = gen.generate(inv, {ps.arn: "AAM-Admin"})
    with open(yaml_path) as f:
        cfn = yaml_mod.safe_load(f)

    ents = _entitlements(cfn)
    assert len(ents) == 2

    role_logical = next(iter(_roles(cfn).keys()))
    user_seen = group_seen = False
    for e in ents.values():
        props = e["Properties"]
        assert props["ApplicationArn"] == _APP_ARN
        pr = props["Entitlement"]["PrincipalRole"]
        # RoleArn wired to the role resource via Fn::GetAtt
        assert pr["RoleArn"] == {"Fn::GetAtt": [role_logical, "Arn"]}
        ic = pr["Principal"]["IdentityCenter"]
        if "UserId" in ic:
            user_seen = True
            assert ic["UserId"] == "11111111-1111-1111-1111-111111111111"
        if "GroupId" in ic:
            group_seen = True
            assert ic["GroupId"] == "22222222-2222-2222-2222-222222222222"
    assert user_seen and group_seen


def test_no_entitlements_without_application_arn(tmp_path):
    """When no application ARN is configured, only roles are emitted."""
    import yaml as yaml_mod

    cfg = _Cfg(iac_output_dir=str(tmp_path), aam_application_arn=None)
    gen = IaCGenerator(cfg, _audit())
    ps = _ps("Admin")
    inv = _inv([ps], [
        AccountAssignmentRecord(
            permission_set_arn=ps.arn, account_id="222222222222",
            principal_type="USER", principal_id="u1", principal_display_name="x",
        )
    ])
    yaml_path = gen.generate(inv, {ps.arn: "AAM-Admin"})
    with open(yaml_path) as f:
        cfn = yaml_mod.safe_load(f)
    assert len(_roles(cfn)) == 1
    assert len(_entitlements(cfn)) == 0


# ─── Property 12: permission boundary applied when configured (IaC) ───────────

def test_property_12_permission_boundary_in_iac(tmp_path):
    """Property 12: permission boundary in generated IaC when configured.

    Validates: Requirements 6.6, 9.5
    """
    import yaml as yaml_mod

    boundary = "arn:aws:iam::111111111111:policy/Boundary"
    cfg = _Cfg(iac_output_dir=str(tmp_path), permission_boundary_arn=boundary)
    gen = IaCGenerator(cfg, _audit())
    ps = _ps("Admin")
    inv = _inv([ps], [
        AccountAssignmentRecord(
            permission_set_arn=ps.arn, account_id="222222222222",
            principal_type="USER", principal_id="u1", principal_display_name="x",
        )
    ])
    yaml_path = gen.generate(inv, {ps.arn: "AAM-Admin"})
    with open(yaml_path) as f:
        cfn = yaml_mod.safe_load(f)
    role = next(iter(_roles(cfn).values()))
    assert role["Properties"]["PermissionsBoundary"] == boundary


def test_property_12_no_boundary_when_unset(tmp_path):
    import yaml as yaml_mod

    cfg = _Cfg(iac_output_dir=str(tmp_path), permission_boundary_arn=None)
    gen = IaCGenerator(cfg, _audit())
    ps = _ps("Admin")
    inv = _inv([ps], [
        AccountAssignmentRecord(
            permission_set_arn=ps.arn, account_id="222222222222",
            principal_type="USER", principal_id="u1", principal_display_name="x",
        )
    ])
    yaml_path = gen.generate(inv, {ps.arn: "AAM-Admin"})
    with open(yaml_path) as f:
        cfn = yaml_mod.safe_load(f)
    role = next(iter(_roles(cfn).values()))
    assert "PermissionsBoundary" not in role["Properties"]


# ─── Property 13: tags applied uniformly (IaC) ────────────────────────────────

def test_property_13_tags_in_iac(tmp_path):
    """Property 13: configured tags appear on every generated role.

    Validates: Requirements 6.3, 9.2
    """
    import yaml as yaml_mod

    tags = {"Owner": "Platform", "Team": "Identity"}
    cfg = _Cfg(iac_output_dir=str(tmp_path), role_tags=tags)
    gen = IaCGenerator(cfg, _audit())
    ps1, ps2 = _ps("Admin"), _ps("ReadOnly")
    inv = _inv([ps1, ps2], [
        AccountAssignmentRecord(
            permission_set_arn=ps1.arn, account_id="222222222222",
            principal_type="USER", principal_id="u1", principal_display_name="x",
        ),
        AccountAssignmentRecord(
            permission_set_arn=ps2.arn, account_id="222222222222",
            principal_type="GROUP", principal_id="g1", principal_display_name="y",
        ),
    ])
    yaml_path = gen.generate(inv, {ps1.arn: "AAM-Admin", ps2.arn: "AAM-ReadOnly"})
    with open(yaml_path) as f:
        cfn = yaml_mod.safe_load(f)
    for role in _roles(cfn).values():
        emitted = {t["Key"]: t["Value"] for t in role["Properties"]["Tags"]}
        assert emitted == tags
