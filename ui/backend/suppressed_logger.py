"""
Suppressed error logging — structured, per-job log files with warning counters.

Replaces bare ``try/except/pass`` blocks with observable suppression that:
  1. Writes to a per-job log file under ``cache/logs/`` (segmented by job_id).
  2. Tracks warning counts by error code in memory for the UI banner.
  3. Classifies errors using the exception's own type/code (no enum mapping).

Usage in a module::

    from .suppressed_logger import SuppressedLogger

    _slog = SuppressedLogger("idc")

    # At the start of a job:
    _slog.start_job(job_id)

    try:
        resp = sso_admin.get_inline_policy_for_permission_set(...)
    except Exception as exc:
        _slog.record(exc, context="get_inline_policy", resource=ps_arn)

The UI-facing summary is retrieved via ``_slog.get_summary()`` which returns
the job_id, log filename, and counts keyed by error code (excluding
expected-empty codes).
"""

import logging
import os
import threading
from typing import Optional

from . import config

# ─── Constants ────────────────────────────────────────────────────────────────

# Error codes that represent "data doesn't exist" — not actual failures.
# These are logged but NOT counted toward the UI warning banner.
EXPECTED_EMPTY = frozenset({"ResourceNotFoundException", "NoSuchEntity"})

LOG_DIR = os.path.join(config.CACHE_DIR, "logs")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _ensure_log_dir() -> None:
    os.makedirs(LOG_DIR, exist_ok=True)


def _error_category(exc: Exception) -> str:
    """Extract the natural error category from an exception.

    - botocore ClientError → the AWS error code string (e.g., "AccessDeniedException")
    - Any other exception  → the class name (e.g., "EndpointConnectionError")
    """
    if hasattr(exc, "response"):
        try:
            return exc.response["Error"]["Code"]
        except (KeyError, TypeError):
            pass
    return type(exc).__name__


# ─── SuppressedLogger ─────────────────────────────────────────────────────────

class SuppressedLogger:
    """Per-module logger that writes suppressed errors to a job-specific log
    file and maintains in-memory warning counts for the UI."""

    def __init__(self, module_name: str):
        self._module_name = module_name
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}
        self._job_id: Optional[str] = None
        self._log_filename: Optional[str] = None
        self._handler: Optional[logging.FileHandler] = None

        _ensure_log_dir()
        self._logger = logging.getLogger(f"truffle.suppressed.{module_name}")
        self._logger.setLevel(logging.DEBUG)
        # Prevent propagation to root logger (keeps terminal clean).
        self._logger.propagate = False

    def start_job(self, job_id: str) -> None:
        """Begin a new job: reset counters and create a fresh log file.

        Args:
            job_id: The unique job identifier (displayed in the UI so the user
                    knows which log file to inspect).
        """
        from datetime import datetime, timezone

        with self._lock:
            self._counts.clear()
            self._job_id = job_id
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            short_id = job_id[:4] if job_id else "0000"
            self._log_filename = f"{self._module_name}_{ts}_{short_id}.log"

        # Replace the file handler to write to the new job-specific file.
        _ensure_log_dir()
        if self._handler:
            self._logger.removeHandler(self._handler)
            self._handler.close()

        log_path = os.path.join(LOG_DIR, self._log_filename)
        self._handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
        self._handler.setFormatter(logging.Formatter(
            "%(asctime)s [SUPPRESSED] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        self._logger.addHandler(self._handler)

    def record(
        self,
        exc: Exception,
        *,
        context: str = "",
        resource: str = "",
    ) -> None:
        """Log a suppressed exception and update the warning counter.

        Args:
            exc: The caught exception.
            context: What operation was attempted (e.g., "get_inline_policy").
            resource: The resource identifier involved (e.g., an ARN).
        """
        category = _error_category(exc)

        # Always log to file.
        parts = [category]
        if context:
            parts.append(context)
        if resource:
            parts.append(f"resource={resource}")
        parts.append(str(exc))
        self._logger.debug(" | ".join(parts))

        # Count toward UI warnings only if not an expected-empty code.
        if category not in EXPECTED_EMPTY:
            with self._lock:
                self._counts[category] = self._counts.get(category, 0) + 1

    def get_summary(self) -> dict:
        """Return the current warning summary for the UI.

        Includes the job_id and log filename so the UI can display them
        in the warning banner, plus counts keyed by error code (only actionable
        errors; expected-empty codes are excluded).
        """
        with self._lock:
            return {
                "job_id": self._job_id,
                "log_file": self._log_filename,
                "counts": dict(self._counts),
                "total": sum(self._counts.values()),
            }

    def get_total_warnings(self) -> int:
        """Total number of actionable suppressed errors recorded."""
        with self._lock:
            return sum(self._counts.values())

    def reset(self) -> None:
        """Clear counters (backwards compat — prefer start_job)."""
        with self._lock:
            self._counts.clear()
