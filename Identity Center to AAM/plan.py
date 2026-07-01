"""Migration plan module (Phase 2).

Generates an editable Excel (XLSX) migration plan from the inventory and
consumes an edited plan supplied via ``--plan``. The plan is the single source
of truth for the permission-set -> RoleName mapping (Requirement 5).

One row per permission set with an editable ``RoleName`` column (default
``AAM-<PermissionSetName>``) and informational principal + account columns.
"""

from __future__ import annotations

import os
import re
from typing import Iterable

from audit_logger import AuditLogger
from config import Config, render_role_name
from models import Inventory, MigrationPlanRow


class PlanError(ValueError):
    """Raised when a supplied migration plan is missing a required column/field
    or contains a RoleName that is invalid for an IAM role name (Req 5.8, 5.9)."""


# Worksheet columns. The first three are authoritative/required; the rest are
# informational context for the operator.
REQUIRED_COLUMNS: tuple[str, ...] = ("PermissionSetArn", "PermissionSetName", "RoleName")
INFO_COLUMNS: tuple[str, ...] = ("Principals", "AccountIds")
ALL_COLUMNS: tuple[str, ...] = REQUIRED_COLUMNS + INFO_COLUMNS

# IAM role names: 1-64 chars from [\w+=,.@-] (the IAM "friendly name" charset).
IAM_ROLE_NAME_RE = re.compile(r"\A[\w+=,.@-]{1,64}\Z")

_LIST_SEP = ", "


class MigrationPlanModule:
    def __init__(self, cfg: Config, audit: AuditLogger) -> None:
        self.cfg = cfg
        self.audit = audit

    # ── Defaults ─────────────────────────────────────────────────────────────

    def default_role_name(self, permission_set_name: str) -> str:
        """Return the default RoleName for a permission set: AAM-<PermissionSetName>
        (Req 5.2). Uses the configured template as the default-name generator."""
        return render_role_name(self.cfg.role_name_template, permission_set_name)

    # ── Generate ─────────────────────────────────────────────────────────────

    def rows_from_inventory(self, inventory: Inventory) -> list[MigrationPlanRow]:
        """Build one plan row per permission set (Req 5.1, 5.3) with informational
        principals and account IDs derived from the assignments (Req 5.4)."""
        principals_by_ps: dict[str, list[str]] = {}
        accounts_by_ps: dict[str, set[str]] = {}
        for a in inventory.assignments:
            principals_by_ps.setdefault(a.permission_set_arn, [])
            label = f"{a.principal_type}:{a.principal_display_name}"
            if label not in principals_by_ps[a.permission_set_arn]:
                principals_by_ps[a.permission_set_arn].append(label)
            accounts_by_ps.setdefault(a.permission_set_arn, set()).add(a.account_id)

        rows: list[MigrationPlanRow] = []
        for ps in inventory.permission_sets:
            rows.append(
                MigrationPlanRow(
                    permission_set_arn=ps.arn,
                    permission_set_name=ps.name,
                    role_name=self.default_role_name(ps.name),
                    principals=tuple(principals_by_ps.get(ps.arn, [])),
                    account_ids=tuple(sorted(accounts_by_ps.get(ps.arn, set()))),
                )
            )
        return rows

    def generate(self, inventory: Inventory, output_path: str | None) -> str:
        """Write an editable XLSX migration plan. Returns the written path."""
        from openpyxl import Workbook  # lazy import

        rows = self.rows_from_inventory(inventory)
        path = output_path or f"migration_plan_{inventory.run_id}.xlsx"
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

        wb = Workbook()
        ws = wb.active
        ws.title = "MigrationPlan"
        ws.append(list(ALL_COLUMNS))
        for r in rows:
            ws.append(
                [
                    r.permission_set_arn,
                    r.permission_set_name,
                    r.role_name,
                    _LIST_SEP.join(r.principals),
                    _LIST_SEP.join(r.account_ids),
                ]
            )
        wb.save(path)
        self.audit.log_success(
            "migration_plan_generated", path, rows=len(rows)
        )
        return path

    # ── Consume ──────────────────────────────────────────────────────────────

    def consume(self, path: str) -> list[MigrationPlanRow]:
        """Read an edited plan XLSX. Validates required columns/fields lazily as
        each row is processed (Req 5.6, 5.8) and rejects invalid IAM role names
        (Req 5.9)."""
        from openpyxl import load_workbook  # lazy import

        if not os.path.isfile(path):
            raise PlanError(f"migration plan not found: {path}")

        wb = load_workbook(path, read_only=True, data_only=True)
        ws = wb.active

        rows_iter = ws.iter_rows(values_only=True)
        try:
            header = next(rows_iter)
        except StopIteration:
            raise PlanError("migration plan is empty (no header row)")

        header_list = [str(h).strip() if h is not None else "" for h in header]
        col_index = {name: idx for idx, name in enumerate(header_list)}

        # Required columns must be present in the header.
        for col in REQUIRED_COLUMNS:
            if col not in col_index:
                raise PlanError(f"migration plan is missing required column: {col!r}")

        plan_rows: list[MigrationPlanRow] = []
        for row_num, raw in enumerate(rows_iter, start=2):
            # Skip fully blank rows.
            if raw is None or all(c is None or str(c).strip() == "" for c in raw):
                continue

            def _field(col: str) -> str:
                idx = col_index[col]
                value = raw[idx] if idx < len(raw) else None
                if value is None or str(value).strip() == "":
                    raise PlanError(
                        f"migration plan row {row_num} is missing required field {col!r}"
                    )
                return str(value).strip()

            ps_arn = _field("PermissionSetArn")
            ps_name = _field("PermissionSetName")
            role_name = _field("RoleName")

            if not IAM_ROLE_NAME_RE.match(role_name):
                raise PlanError(
                    f"migration plan row {row_num}: RoleName {role_name!r} is invalid "
                    f"for an IAM role name (allowed: 1-64 chars of [A-Za-z0-9_+=,.@-])"
                )

            principals = _optional_list(raw, col_index.get("Principals"))
            account_ids = _optional_list(raw, col_index.get("AccountIds"))

            plan_rows.append(
                MigrationPlanRow(
                    permission_set_arn=ps_arn,
                    permission_set_name=ps_name,
                    role_name=role_name,
                    principals=principals,
                    account_ids=account_ids,
                )
            )

        wb.close()
        self.audit.log_success("migration_plan_consumed", path, rows=len(plan_rows))
        return plan_rows

    # ── Mapping materialization ──────────────────────────────────────────────

    def role_name_for(self, rows: Iterable[MigrationPlanRow]) -> dict[str, str]:
        """Build a permission_set_arn -> RoleName mapping. Duplicate role names
        across rows are surfaced as a conflict at this (apply/IaC) boundary
        (Req 5.10)."""
        mapping: dict[str, str] = {}
        seen_names: dict[str, str] = {}  # role_name -> first permission_set_arn
        duplicates: list[str] = []
        for r in rows:
            if r.role_name in seen_names and seen_names[r.role_name] != r.permission_set_arn:
                duplicates.append(
                    f"{r.role_name!r} (used by {seen_names[r.role_name]} and "
                    f"{r.permission_set_arn})"
                )
            else:
                seen_names.setdefault(r.role_name, r.permission_set_arn)
            mapping[r.permission_set_arn] = r.role_name

        if duplicates:
            detail = "; ".join(duplicates)
            self.audit.log(
                "migration_plan_duplicate_role_names",
                self.cfg.run_id,
                "FAILURE",
                error_detail=detail,
            )
            raise PlanError(f"duplicate role names in migration plan: {detail}")
        return mapping


def _optional_list(raw: tuple, idx: int | None) -> tuple[str, ...]:
    if idx is None or idx >= len(raw):
        return ()
    value = raw[idx]
    if value is None or str(value).strip() == "":
        return ()
    return tuple(part.strip() for part in str(value).split(",") if part.strip())
