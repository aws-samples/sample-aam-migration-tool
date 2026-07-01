"""Mapping reporter: generate a single artifact summarizing the migration."""

from __future__ import annotations

import csv
import json
import os
from typing import Iterable

from audit_logger import AuditLogger
from config import Config
from models import (
    AccountAssignmentRecord,
    ApplicationResult,
    EntitlementCreationResult,
    Inventory,
    MappingReportRow,
    RoleCreationResult,
)


class MappingReporter:
    def __init__(self, cfg: Config, audit: AuditLogger) -> None:
        self.cfg = cfg
        self.audit = audit

    # ── Build ────────────────────────────────────────────────────────────────

    def build_rows(
        self,
        inventory: Inventory,
        role_results: Iterable[RoleCreationResult],
        application: ApplicationResult,
        entitlement_results: Iterable[EntitlementCreationResult],
    ) -> list[MappingReportRow]:
        ps_name_by_arn: dict[str, str] = {ps.arn: ps.name for ps in inventory.permission_sets}
        role_by_key: dict[tuple[str, str], RoleCreationResult] = {
            (r.permission_set_arn, r.account_id): r for r in role_results
        }
        ent_by_key: dict[tuple[str, str, str], EntitlementCreationResult] = {}
        for e in entitlement_results:
            ent_by_key[(e.permission_set_arn, e.account_id, e.principal_id)] = e

        application_failed = application.status == "FAILED"
        application_id_str = application.application_arn or ""

        rows: list[MappingReportRow] = []
        for a in inventory.assignments:
            role = role_by_key.get((a.permission_set_arn, a.account_id))
            ent = ent_by_key.get((a.permission_set_arn, a.account_id, a.principal_id))

            if application_failed:
                status = "FAILED"
            elif ent is not None:
                status = ent.status
            elif role is not None:
                status = role.status
            else:
                status = "FAILED"

            rows.append(
                MappingReportRow(
                    principal_type=a.principal_type,
                    principal_display_name=a.principal_display_name,
                    principal_id=a.principal_id,
                    permission_set_name=ps_name_by_arn.get(a.permission_set_arn, ""),
                    permission_set_arn=a.permission_set_arn,
                    target_account_id=a.account_id,
                    role_arn=role.role_arn if role else None,
                    application_id=application_id_str if application_id_str else None,
                    entitlement_id=ent.entitlement_id if ent else None,
                    status=status,  # type: ignore[arg-type]
                )
            )
        return rows

    # ── Write ────────────────────────────────────────────────────────────────

    def write(self, rows: list[MappingReportRow]) -> str | None:
        if not rows:
            self.audit.log_success(
                "mapping_report_skipped",
                self.cfg.run_id,
                reason="no data to report",
            )
            return None

        fmt = self.cfg.mapping_output_format
        path = self.cfg.mapping_output_path or self._default_path(fmt)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

        try:
            if fmt == "XLSX":
                self._write_xlsx(rows, path)
            elif fmt == "CSV":
                self._write_csv(rows, path)
            elif fmt == "JSON":
                self._write_json(rows, path)
            else:
                raise ValueError(f"Unsupported mapping output format: {fmt!r}")
            self.audit.log_success("mapping_report_written", path, format=fmt, rows=len(rows))
            return path
        except Exception as exc:  # noqa: BLE001
            self.audit.log_failure("mapping_report_failed", path, exc)
            raise

    def _default_path(self, fmt: str) -> str:
        ext = {"XLSX": "xlsx", "CSV": "csv", "JSON": "json"}[fmt]
        return f"mapping_{self.cfg.run_id}.{ext}"

    def _write_xlsx(self, rows: list[MappingReportRow], path: str) -> None:
        from openpyxl import Workbook  # imported lazily

        wb = Workbook()
        ws = wb.active
        ws.title = "Mapping"
        ws.append(list(MappingReportRow.header()))
        for r in rows:
            ws.append(list(r.as_row()))
        wb.save(path)

    def _write_csv(self, rows: list[MappingReportRow], path: str) -> None:
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(MappingReportRow.header())
            for r in rows:
                writer.writerow(list(r.as_row()))

    def _write_json(self, rows: list[MappingReportRow], path: str) -> None:
        payload = [
            dict(zip(MappingReportRow.header(), r.as_row())) for r in rows
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
