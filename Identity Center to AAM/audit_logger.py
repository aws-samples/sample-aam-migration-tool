"""Audit logger emitting structured entries to stdout, CSV, and CloudWatch Logs.

Per Requirements 12 and 13, every important action must produce a structured
log entry. Sinks are independent: a failure in one sink (e.g., CloudWatch
delivery) writes the entry to stderr but does not block the others.
"""

from __future__ import annotations

import csv
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, TextIO

from models import AuditLogEntry, LogStatus


_STDOUT_FALLBACK = True


class AuditLogger:
    """Multi-sink audit logger. Thread-safe."""

    def __init__(
        self,
        run_id: str,
        caller_arn: str,
        cfg: Any,
        cloudwatch_client: Any | None = None,
        *,
        stderr: TextIO | None = None,
        stdout: TextIO | None = None,
    ) -> None:
        self.run_id = run_id
        self.caller_arn = caller_arn
        self._cfg = cfg
        self.verbose = bool(getattr(cfg, "verbose", False))
        self._lock = threading.Lock()
        self._stderr = stderr if stderr is not None else sys.stderr
        self._stdout = stdout if stdout is not None else sys.stdout

        # CSV sink
        self._csv_file: TextIO | None = None
        self._csv_writer: csv.DictWriter | None = None
        self._csv_header_written = False
        if getattr(cfg, "audit_to_file", False) and getattr(cfg, "audit_file_path", None):
            self._open_csv(cfg.audit_file_path)

        # CloudWatch sink (lazy stream creation)
        self._cw_client = cloudwatch_client
        self._cw_log_group: str | None = None
        self._cw_log_stream: str | None = None
        self._cw_sequence_token: str | None = None
        if getattr(cfg, "audit_to_cloudwatch", False):
            self._cw_log_group = cfg.cloudwatch_log_group
            self._cw_log_stream = f"idc-to-aam-{run_id}"
            if self._cw_client is None:
                # Defer construction; let the orchestrator inject one for testability.
                import boto3
                from aws_session import boto_config

                self._cw_client = boto3.client(
                    "logs",
                    region_name=getattr(cfg, "region", "us-east-1"),
                    config=boto_config(getattr(cfg, "workers", 5)),
                )
            self._init_cloudwatch_stream()

        # Stdout is reserved for clean, human-readable program output. Structured
        # audit JSON only goes to the console when --verbose is set; otherwise the
        # console stays quiet (failures still surface concisely on stderr).
        self._verbose_console = self.verbose

    # ── Sink lifecycle ───────────────────────────────────────────────────────

    def _open_csv(self, path: str) -> None:
        existed = os.path.isfile(path)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._csv_file = open(path, "a", newline="", encoding="utf-8")  # nosemgrep: open-never-closed
        fieldnames = [
            "timestamp",
            "run_id",
            "action",
            "target",
            "status",
            "caller_arn",
            "error_detail",
            "extra",
        ]
        self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=fieldnames)
        if not existed:
            self._csv_writer.writeheader()
        self._csv_header_written = True

    def _init_cloudwatch_stream(self) -> None:
        if not self._cw_client or not self._cw_log_group or not self._cw_log_stream:
            return
        try:
            self._cw_client.create_log_group(logGroupName=self._cw_log_group)
        except Exception:  # noqa: BLE001 - log group may already exist
            pass
        try:
            self._cw_client.create_log_stream(
                logGroupName=self._cw_log_group,
                logStreamName=self._cw_log_stream,
            )
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        with self._lock:
            if self._csv_file is not None:
                try:
                    self._csv_file.flush()
                    self._csv_file.close()
                except Exception:  # noqa: BLE001
                    pass
                finally:
                    self._csv_file = None
                    self._csv_writer = None

    def __enter__(self) -> "AuditLogger":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ── Public API ───────────────────────────────────────────────────────────

    def log(
        self,
        action: str,
        target: str,
        status: LogStatus,
        error_detail: str = "",
        extra: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        entry = AuditLogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            run_id=self.run_id,
            action=action,
            target=target,
            status=status,
            caller_arn=self.caller_arn,
            error_detail=error_detail or "",
            extra=dict(extra) if extra else {},
        )
        self._emit(entry)
        return entry

    def log_success(self, action: str, target: str, **extra: Any) -> AuditLogEntry:
        return self.log(action=action, target=target, status="SUCCESS", extra=extra or None)

    def log_failure(
        self,
        action: str,
        target: str,
        exc: BaseException,
        **extra: Any,
    ) -> AuditLogEntry:
        detail = f"{type(exc).__name__}: {exc}"
        return self.log(
            action=action,
            target=target,
            status="FAILURE",
            error_detail=detail,
            extra=extra or None,
        )

    # ── Emission ─────────────────────────────────────────────────────────────

    def _emit(self, entry: AuditLogEntry) -> None:
        with self._lock:
            if self._csv_writer is not None:
                self._emit_csv(entry)
            if self._cw_client is not None and self._cw_log_group and self._cw_log_stream:
                self._emit_cloudwatch(entry)
            self._emit_console(entry)

    def _emit_console(self, entry: AuditLogEntry) -> None:
        """Keep the console clean by default. In verbose mode, print the full
        structured entry as JSON to stdout. Otherwise stay silent on success and
        print a concise one-line notice to stderr on failure."""
        if self._verbose_console:
            try:
                print(json.dumps(entry.to_dict(), default=str), file=self._stdout, flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"audit_stdout_failure: {exc}", file=self._stderr)
        elif entry.status == "FAILURE":
            detail = entry.error_detail or entry.target
            print(f"  ! {entry.action}: {detail}", file=self._stderr, flush=True)

    def _emit_csv(self, entry: AuditLogEntry) -> None:
        if self._csv_writer is None or self._csv_file is None:
            return
        try:
            row = entry.to_dict()
            row["extra"] = json.dumps(row["extra"], default=str)
            self._csv_writer.writerow(row)
            self._csv_file.flush()
        except Exception as exc:  # noqa: BLE001
            print(
                f"audit_csv_failure: {type(exc).__name__}: {exc} "
                f"entry={json.dumps(entry.to_dict(), default=str)}",
                file=self._stderr,
            )

    def _emit_cloudwatch(self, entry: AuditLogEntry) -> None:
        try:
            kwargs = {
                "logGroupName": self._cw_log_group,
                "logStreamName": self._cw_log_stream,
                "logEvents": [
                    {
                        "timestamp": int(time.time() * 1000),
                        "message": json.dumps(entry.to_dict(), default=str),
                    }
                ],
            }
            if self._cw_sequence_token:
                kwargs["sequenceToken"] = self._cw_sequence_token
            resp = self._cw_client.put_log_events(**kwargs)
            self._cw_sequence_token = resp.get("nextSequenceToken")
        except Exception as exc:  # noqa: BLE001 - Req 13.5: isolate the failure
            print(
                f"audit_cloudwatch_failure: {type(exc).__name__}: {exc} "
                f"entry={json.dumps(entry.to_dict(), default=str)}",
                file=self._stderr,
            )
