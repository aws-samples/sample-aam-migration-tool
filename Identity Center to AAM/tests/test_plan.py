"""Tests for the migration plan module (plan.py)."""

from __future__ import annotations

import io
from dataclasses import dataclass

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from audit_logger import AuditLogger
from models import AccountAssignmentRecord, Inventory, PermissionSetRecord
from plan import IAM_ROLE_NAME_RE, MigrationPlanModule, PlanError, REQUIRED_COLUMNS


# ─── Scaffolding ──────────────────────────────────────────────────────────────

@dataclass
class _Cfg:
    role_name_template: str = "AAM-{permission_set_name}"
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


def _ps(name: str) -> PermissionSetRecord:
    return PermissionSetRecord(
        arn=f"arn:aws:sso:::permissionSet/ssoins-x/ps-{name}",
        name=name,
        description="",
        session_duration="PT1H",
        inline_policy=None,
        aws_managed_policy_arns=(),
        customer_managed_policy_references=(),
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


# ─── Property 6: Migration plan round-trip preserves default role names ───────

@settings(max_examples=100)
@given(
    names=st.lists(
        st.text(min_size=1, max_size=20, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789"),
        min_size=1,
        max_size=6,
        unique=True,
    )
)
def test_property_6_plan_round_trip_default_names(tmp_path_factory, names):
    """Property 6: Migration plan round-trip preserves default role names.

    Validates: Requirements 5.2, 5.3, 5.6, 5.7
    """
    tmp_path = tmp_path_factory.mktemp("plan")
    pm = MigrationPlanModule(_Cfg(), _audit())
    permission_sets = [_ps(n) for n in names]
    inv = _inv(permission_sets, [])

    out = str(tmp_path / "plan.xlsx")
    pm.generate(inv, out)
    rows = pm.consume(out)

    # One row per permission set, none missing or duplicated.
    assert len(rows) == len(permission_sets)
    by_arn = {r.permission_set_arn: r for r in rows}
    for ps in permission_sets:
        assert by_arn[ps.arn].role_name == f"AAM-{ps.name}"

    mapping = pm.role_name_for(rows)
    assert mapping == {ps.arn: f"AAM-{ps.name}" for ps in permission_sets}


# ─── Property 7: Plan validation rejects missing columns and invalid names ────

def test_property_7_missing_required_column(tmp_path):
    """Property 7 (part 1): missing required column → PlanError.

    Validates: Requirement 5.8
    """
    from openpyxl import Workbook

    pm = MigrationPlanModule(_Cfg(), _audit())
    # Build a plan workbook missing the RoleName column.
    wb = Workbook()
    ws = wb.active
    ws.append(["PermissionSetArn", "PermissionSetName"])  # no RoleName
    ws.append(["arn:aws:sso:::permissionSet/ssoins-x/ps-Admin", "Admin"])
    path = str(tmp_path / "bad.xlsx")
    wb.save(path)

    with pytest.raises(PlanError, match="RoleName"):
        pm.consume(path)


@settings(max_examples=100)
@given(
    bad_name=st.text(
        min_size=1, max_size=10, alphabet=st.characters(min_codepoint=33, max_codepoint=126)
    ).filter(lambda s: not IAM_ROLE_NAME_RE.match(s))
)
def test_property_7_invalid_role_name(tmp_path_factory, bad_name):
    """Property 7 (part 2): invalid IAM RoleName → PlanError.

    Validates: Requirement 5.9

    The strategy is restricted to printable ASCII (codepoints 33-126) so the
    fixture can be written by openpyxl; these still include characters such as
    '/', ' ', '!', '#' that are invalid in an IAM role name.
    """
    from openpyxl import Workbook

    tmp_path = tmp_path_factory.mktemp("plan")
    pm = MigrationPlanModule(_Cfg(), _audit())
    wb = Workbook()
    ws = wb.active
    ws.append(list(REQUIRED_COLUMNS))
    ws.append(["arn:aws:sso:::permissionSet/ssoins-x/ps-Admin", "Admin", bad_name])
    path = str(tmp_path / "bad.xlsx")
    wb.save(path)

    with pytest.raises(PlanError):
        pm.consume(path)


# ─── Property 8: Duplicate role names are surfaced as a conflict ──────────────

def test_property_8_duplicate_role_names_conflict(tmp_path):
    """Property 8: duplicate role names surfaced at materialization.

    Validates: Requirement 5.10
    """
    from openpyxl import Workbook

    pm = MigrationPlanModule(_Cfg(), _audit())
    wb = Workbook()
    ws = wb.active
    ws.append(list(REQUIRED_COLUMNS))
    ws.append(["arn:aws:sso:::permissionSet/ssoins-x/ps-A", "A", "SharedName"])
    ws.append(["arn:aws:sso:::permissionSet/ssoins-x/ps-B", "B", "SharedName"])
    path = str(tmp_path / "dupe.xlsx")
    wb.save(path)

    rows = pm.consume(path)
    with pytest.raises(PlanError, match="duplicate role names"):
        pm.role_name_for(rows)


# ─── Unit: informational columns populated from assignments (Req 5.4) ─────────

def test_plan_informational_columns(tmp_path):
    pm = MigrationPlanModule(_Cfg(), _audit())
    ps = _ps("Admin")
    inv = _inv(
        [ps],
        [
            AccountAssignmentRecord(
                permission_set_arn=ps.arn,
                account_id="222222222222",
                principal_type="USER",
                principal_id="u1",
                principal_display_name="Omar",
            ),
            AccountAssignmentRecord(
                permission_set_arn=ps.arn,
                account_id="333333333333",
                principal_type="GROUP",
                principal_id="g1",
                principal_display_name="Eng",
            ),
        ],
    )
    out = str(tmp_path / "plan.xlsx")
    pm.generate(inv, out)
    rows = pm.consume(out)
    assert len(rows) == 1
    row = rows[0]
    assert "USER:Omar" in row.principals
    assert "GROUP:Eng" in row.principals
    assert set(row.account_ids) == {"222222222222", "333333333333"}
