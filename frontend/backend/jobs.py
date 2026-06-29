"""
Background job runner for long-running scans (option A: background job + poll).

The scan endpoint starts a job and returns immediately with a ``job_id``; the
frontend polls ``/api/policy-analysis/status`` for progress and the final
result. Jobs run in daemon threads with state held in memory.

If the server restarts, in-memory jobs are lost — but that's fine: the scan's
checkpoint persists, so re-running the same scan resumes from where it stopped.
"""

import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

from . import policy_analysis
from . import iam_federation

_JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def start_scan(params: dict) -> str:
    """Create a policy-scan job, start it on a background thread, return its id."""
    job_id = uuid.uuid4().hex[:12]
    with _LOCK:
        _JOBS[job_id] = {
            "id": job_id,
            "type": "policy-scan",
            "status": "running",
            "progress": {
                "completed_units": 0,
                "total_units": 0,
                "skipped_units": 0,
                "message": "starting",
            },
            "started_at": _now(),
            "finished_at": None,
            "error": None,
            "result": None,
        }
    thread = threading.Thread(target=_run, args=(job_id, params), daemon=True)
    thread.start()
    return job_id


def _update_progress(job_id: str, update: dict) -> None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if job:
            job["progress"].update(update)


def _run(job_id: str, params: dict) -> None:
    try:
        result = policy_analysis.run_scan_job(
            params, on_progress=lambda u: _update_progress(job_id, u)
        )
        with _LOCK:
            job = _JOBS.get(job_id)
            if job:
                job["status"] = "done"
                job["result"] = result
                job["finished_at"] = _now()
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI via status
        with _LOCK:
            job = _JOBS.get(job_id)
            if job:
                job["status"] = "error"
                job["error"] = str(exc)
                job["finished_at"] = _now()


def get(job_id: str) -> Optional[dict]:
    """Return a snapshot of the job, or ``None`` if unknown (e.g. after restart)."""
    with _LOCK:
        job = _JOBS.get(job_id)
        return dict(job) if job else None


# ─── IAM Federation discovery job ────────────────────────────────────────────

def start_iam_discover(params: dict) -> str:
    """Create an IAM federation discovery job, start it, return the id."""
    job_id = uuid.uuid4().hex[:12]
    with _LOCK:
        _JOBS[job_id] = {
            "id": job_id,
            "type": "iam-discover",
            "status": "running",
            "progress": {
                "completed_units": 0,
                "total_units": 0,
                "skipped_units": 0,
                "message": "starting",
            },
            "started_at": _now(),
            "finished_at": None,
            "error": None,
            "result": None,
        }
    thread = threading.Thread(target=_run_iam_discover, args=(job_id, params), daemon=True)
    thread.start()
    return job_id


def _run_iam_discover(job_id: str, params: dict) -> None:
    try:
        result = iam_federation.discover_roles(
            params, on_progress=lambda u: _update_progress(job_id, u)
        )
        with _LOCK:
            job = _JOBS.get(job_id)
            if job:
                job["status"] = "done"
                job["result"] = result
                job["finished_at"] = _now()
    except Exception as exc:
        with _LOCK:
            job = _JOBS.get(job_id)
            if job:
                job["status"] = "error"
                job["error"] = str(exc)
                job["finished_at"] = _now()
