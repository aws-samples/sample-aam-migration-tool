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
        """Read an edited plan (XLSX or CSV). Validates required columns/fields
        and rejects invalid IAM role names (Req 5.6, 5.8, 5.9).

        CSV files use flexible header matching (column order doesn't matter).
        Accepted CSV headers map to the canonical fields as follows:
          - Permission Set ARN / permission_set_arn / PermissionSetArn
          - Permission Set / permission_set_name / PermissionSetName (optional if ARN present)
          - Role Name / role_name / RoleName
          - Account ID / account_id / AccountIds / Account (optional)
          - Principal / Principals (optional)
          - Principal Type / principal_type / Type (optional)
        """
        if not os.path.isfile(path):
            raise PlanError(f"migration plan not found: {path}")

        ext = os.path.splitext(path)[1].lower()
        if ext == ".csv":
            return self._consume_csv(path)
        else:
            return self._consume_xlsx(path)

    def _consume_csv(self, path: str) -> list[MigrationPlanRow]:
        """Read a CSV migration plan with flexible header matching."""
        import csv

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise PlanError("migration plan CSV is empty (no header row)")

            # Flexible header resolution — map canonical fields to actual column names
            def _find_col(*candidates: str) -> str | None:
                for col in reader.fieldnames:  # type: ignore[union-attr]
                    col_lower = col.lower().strip()
                    for c in candidates:
                        if col_lower == c.lower():
                            return col
                return None

            arn_col = _find_col("permission set arn", "permission_set_arn", "permissionsetarn")
            name_col = _find_col("permission set", "permission set name", "permission_set_name", "permissionsetname")
            role_col = _find_col("role name", "role_name", "rolename")
            account_col = _find_col("account id", "account_id", "accountids", "account")
            principal_col = _find_col("principal", "principals")
            type_col = _find_col("principal type", "principal_type", "type")

            if not arn_col:
                raise PlanError("migration plan CSV is missing required column: 'Permission Set ARN'")
            if not role_col:
                raise PlanError("migration plan CSV is missing required column: 'Role Name'")

            plan_rows: list[MigrationPlanRow] = []
            for row_num, row in enumerate(reader, start=2):
                ps_arn = (row.get(arn_col) or "").strip()
                role_name = (row.get(role_col) or "").strip()

                if not ps_arn and not role_name:
                    continue  # skip empty rows

                if not ps_arn:
                    raise PlanError(f"migration plan row {row_num} is missing required field 'Permission Set ARN'")
                if not role_name:
                    raise PlanError(f"migration plan row {row_num} is missing required field 'Role Name'")

                if not IAM_ROLE_NAME_RE.match(role_name):
                    raise PlanError(
                        f"migration plan row {row_num}: RoleName {role_name!r} is invalid "
                        f"for an IAM role name (allowed: 1-64 chars of [A-Za-z0-9_+=,.@-])"
                    )

                ps_name = (row.get(name_col) or "").strip() if name_col else ""
                if not ps_name:
                    # Derive from the ARN (last segment after /)
                    ps_name = ps_arn.rsplit("/", 1)[-1]

                # Build principals tuple: combine principal + type if available
                principals: tuple[str, ...] = ()
                principal_val = (row.get(principal_col) or "").strip() if principal_col else ""
                if principal_val:
                    ptype = (row.get(type_col) or "GROUP").strip().upper() if type_col else "GROUP"
                    principals = (f"{ptype}:{principal_val}",)

                # Account IDs
                account_ids: tuple[str, ...] = ()
                account_val = (row.get(account_col) or "").strip() if account_col else ""
                if account_val:
                    account_ids = (account_val,)

                plan_rows.append(
                    MigrationPlanRow(
                        permission_set_arn=ps_arn,
                        permission_set_name=ps_name,
                        role_name=role_name,
                        principals=principals,
                        account_ids=account_ids,
                    )
                )

        self.audit.log_success("migration_plan_consumed", path, rows=len(plan_rows))
        return plan_rows

    def _consume_xlsx(self, path: str) -> list[MigrationPlanRow]:
        """Read an edited plan XLSX. Validates required columns/fields lazily as
        each row is processed (Req 5.6, 5.8) and rejects invalid IAM role names
        (Req 5.9)."""
        from openpyxl import load_workbook  # lazy import

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

    # ── Inventory scoping ────────────────────────────────────────────────────

    def filter_inventory(
        self, inventory: Inventory, plan_rows: Iterable[MigrationPlanRow]
    ) -> Inventory:
        """Return a copy of ``inventory`` whose assignments are restricted to what
        the migration plan authorizes.

        The plan is authoritative: an assignment is kept only if it matches a plan
        row on all three axes — permission set, account, and principal:

          1. ``permission_set_arn`` appears in the plan, AND
          2. ``account_id`` is listed in that row's ``account_ids``, AND
          3. ``{principal_type}:{principal_display_name}`` is listed in that row's
             ``principals``.

        An empty ``principals`` or ``account_ids`` column matches *nothing* for
        that permission set (so a fully-cleared row scopes it out entirely).
        Permission sets absent from the plan are dropped as well.
        """
        # Build per-permission-set allow-sets from the plan.
        principals_by_ps: dict[str, set[str]] = {}
        accounts_by_ps: dict[str, set[str]] = {}
        for row in plan_rows:
            principals_by_ps.setdefault(row.permission_set_arn, set()).update(row.principals)
            accounts_by_ps.setdefault(row.permission_set_arn, set()).update(row.account_ids)

        kept = []
        dropped = 0
        for a in inventory.assignments:
            ps = a.permission_set_arn
            if ps not in principals_by_ps:
                dropped += 1
                continue
            allowed_principals = principals_by_ps[ps]
            allowed_accounts = accounts_by_ps.get(ps, set())
            principal_label = f"{a.principal_type}:{a.principal_display_name}"
            if (
                a.account_id in allowed_accounts
                and principal_label in allowed_principals
            ):
                kept.append(a)
            else:
                dropped += 1

        # Also restrict permission_sets to those referenced by the plan so
        # downstream role creation doesn't act on out-of-scope permission sets.
        kept_ps = tuple(
            ps for ps in inventory.permission_sets if ps.arn in principals_by_ps
        )

        self.audit.log_success(
            "migration_plan_inventory_filtered",
            self.cfg.run_id,
            assignments_kept=len(kept),
            assignments_dropped=dropped,
            permission_sets_kept=len(kept_ps),
        )

        return Inventory(
            hub_account_id=inventory.hub_account_id,
            idc_instance_arn=inventory.idc_instance_arn,
            identity_store_id=inventory.identity_store_id,
            permission_sets=kept_ps,
            assignments=tuple(kept),
            run_id=inventory.run_id,
            captured_at=inventory.captured_at,
        )


def _optional_list(raw: tuple, idx: int | None) -> tuple[str, ...]:
    if idx is None or idx >= len(raw):
        return ()
    value = raw[idx]
    if value is None or str(value).strip() == "":
        return ()
    return tuple(part.strip() for part in str(value).split(",") if part.strip())
