"""Tests for the audit logger."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass

import pytest

from audit_logger import AuditLogger
from models import AuditLogEntry


# ─── Test fixtures ────────────────────────────────────────────────────────────

@dataclass
class _FakeCfg:
    audit_to_cloudwatch: bool = False
    cloudwatch_log_group: str | None = None
    audit_to_file: bool = False
    audit_file_path: str | None = None
    workers: int = 5
    region: str = "us-east-1"
    verbose: bool = False


class _RecordingClient:
    def __init__(self):
        self.events = []

    def create_log_group(self, **kw):
        return {}

    def create_log_stream(self, **kw):
        return {}

    def put_log_events(self, **kw):
        self.events.append(kw)
        return {"nextSequenceToken": str(len(self.events))}


class _FailingClient(_RecordingClient):
    def put_log_events(self, **kw):
        raise RuntimeError("cloudwatch is down")


# ─── Property 19: status matches outcome ──────────────────────────────────────

def test_property_19_status_matches_outcome(tmp_path):
    """Property 19: Audit log status matches outcome.

    Validates: Requirements 12.3, 12.4, 12.5
    """
    csv_path = str(tmp_path / "audit.csv")
    cfg = _FakeCfg(audit_to_file=True, audit_file_path=csv_path)
    stdout = io.StringIO()
    stderr = io.StringIO()
    log = AuditLogger("rid", "arn:aws:iam::1:role/r", cfg, stdout=stdout, stderr=stderr)

    success = log.log_success("foo", "target")
    assert success.status == "SUCCESS"
    assert success.error_detail == ""

    failure = log.log_failure("bar", "target", RuntimeError("boom"))
    assert failure.status == "FAILURE"
    assert "RuntimeError" in failure.error_detail
    assert "boom" in failure.error_detail
    log.close()


# ─── Property 20: required fields present ─────────────────────────────────────

def test_property_20_audit_fields_present():
    """Property 20: Audit log fields present.

    Validates: Requirement 12.2
    """
    cfg = _FakeCfg()
    stdout = io.StringIO()
    log = AuditLogger("rid", "arn:aws:iam::1:role/r", cfg, stdout=stdout)
    entry = log.log_success("foo", "tgt")
    for field in ("timestamp", "run_id", "action", "target", "status", "caller_arn"):
        v = getattr(entry, field)
        assert v, f"{field} must be non-empty"
    # ISO 8601 with timezone
    assert "+" in entry.timestamp or entry.timestamp.endswith("Z")


# ─── Property 21: CloudWatch failure isolation ────────────────────────────────

def test_property_21_cloudwatch_failure_isolation(tmp_path):
    """Property 21: CloudWatch failure isolation.

    Validates: Requirement 13.5
    """
    csv_path = str(tmp_path / "audit.csv")
    cfg = _FakeCfg(
        audit_to_file=True,
        audit_file_path=csv_path,
        audit_to_cloudwatch=True,
        cloudwatch_log_group="/aam/migration",
    )
    stderr = io.StringIO()
    stdout = io.StringIO()
    log = AuditLogger(
        "rid", "arn:aws:iam::1:role/r", cfg,
        cloudwatch_client=_FailingClient(),
        stdout=stdout,
        stderr=stderr,
    )
    log.log_success("inventory_permission_set", "ps-arn-1")
    log.close()

    with open(csv_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["action"] == "inventory_permission_set"
    assert "cloudwatch" in stderr.getvalue().lower()


# ─── Sink-level units ─────────────────────────────────────────────────────────

def test_csv_header_written_once(tmp_path):
    csv_path = str(tmp_path / "audit.csv")
    cfg = _FakeCfg(audit_to_file=True, audit_file_path=csv_path)
    log = AuditLogger("rid", "caller", cfg)
    log.log_success("a", "t1")
    log.log_success("b", "t2")
    log.close()

    log2 = AuditLogger("rid", "caller", cfg)  # appends
    log2.log_success("c", "t3")
    log2.close()

    with open(csv_path, encoding="utf-8") as f:
        text = f.read()
    # Header should appear exactly once
    assert text.count("timestamp,run_id,action,target,status,caller_arn,error_detail,extra") == 1


def test_cloudwatch_event_order_preserved(tmp_path):
    cfg = _FakeCfg(audit_to_cloudwatch=True, cloudwatch_log_group="g")
    client = _RecordingClient()
    log = AuditLogger("rid", "caller", cfg, cloudwatch_client=client)
    for i in range(5):
        log.log_success(f"action-{i}", f"target-{i}")
    log.close()
    actions = [
        json.loads(call["logEvents"][0]["message"])["action"] for call in client.events
    ]
    assert actions == [f"action-{i}" for i in range(5)]


def test_console_quiet_by_default(tmp_path):
    """By default the console stays clean: successes are silent on stdout."""
    cfg = _FakeCfg()
    stdout = io.StringIO()
    stderr = io.StringIO()
    log = AuditLogger("rid", "caller", cfg, stdout=stdout, stderr=stderr)
    log.log_success("foo", "bar")
    log.close()
    assert stdout.getvalue() == ""


def test_console_failure_shown_on_stderr(tmp_path):
    """Failures surface concisely on stderr even in the default (quiet) mode."""
    cfg = _FakeCfg()
    stdout = io.StringIO()
    stderr = io.StringIO()
    log = AuditLogger("rid", "caller", cfg, stdout=stdout, stderr=stderr)
    log.log_failure("create_entitlement", "tgt", RuntimeError("Unauthorized"))
    log.close()
    assert stdout.getvalue() == ""
    err = stderr.getvalue()
    assert "create_entitlement" in err
    assert "Unauthorized" in err


def test_verbose_prints_json_to_stdout(tmp_path):
    """--verbose restores the full structured JSON on stdout for debugging."""
    cfg = _FakeCfg(verbose=True)
    stdout = io.StringIO()
    log = AuditLogger("rid", "caller", cfg, stdout=stdout)
    log.log_success("foo", "bar")
    log.close()
    payload = json.loads(stdout.getvalue().strip())
    assert payload["action"] == "foo"
    assert payload["status"] == "SUCCESS"
