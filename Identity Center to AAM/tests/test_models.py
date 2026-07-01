"""Tests for the dataclass models, focusing on JSON round-trip (Property 4)."""

from __future__ import annotations

import json

from hypothesis import given, settings

from models import Inventory
import strategies as ts


@settings(max_examples=50)
@given(ts.inventory())
def test_inventory_json_roundtrip(inv: Inventory):
    """Property 4: Inventory JSON round-trip.

    Validates: Requirements 4.1, 4.3
    """
    blob = json.loads(inv.to_json())
    rebuilt = Inventory.from_dict(blob)
    assert rebuilt == inv


def test_mapping_row_header_matches_as_row_arity():
    """Header field count matches as_row tuple length."""
    from models import MappingReportRow

    sample = MappingReportRow(
        principal_type="USER",
        principal_display_name="bob",
        principal_id="abc",
        permission_set_name="ps",
        permission_set_arn="arn",
        target_account_id="111122223333",
        role_arn="arn:aws:iam::111122223333:role/x",
        application_id="app-1",
        entitlement_id="ent-1",
        status="CREATED",
    )
    assert len(MappingReportRow.header()) == len(sample.as_row())


def test_audit_log_entry_to_dict_contains_required_fields():
    from models import AuditLogEntry

    entry = AuditLogEntry(
        timestamp="2025-01-01T00:00:00+00:00",
        run_id="r1",
        action="x",
        target="t",
        status="SUCCESS",
        caller_arn="arn:aws:iam::111111111111:role/r",
    )
    d = entry.to_dict()
    for k in ("timestamp", "run_id", "action", "target", "status", "caller_arn", "error_detail", "extra"):
        assert k in d
