"""
Scan checkpoint store — enables resuming an interrupted policy scan.

A scan is decomposed into units: one "global" unit per account plus one unit
per (account, region). As each unit finishes, its matches are saved here keyed
by a hash of the scan parameters. On a re-run with the same parameters, fresh
(non-expired) units are skipped.

Design notes:
  * Keyed by the *scope* parameters (search terms, services, regions,
    management flag) — NOT by which accounts were selected. Units within a file
    are keyed by resolved account_id, so re-running with a subset still resumes.
  * Matches-level (not raw policies): covers the resume use case without
    modifying the shared scanner. Changing search terms produces a different
    key, so it naturally starts fresh.
  * Thread-safe: account units complete on parallel threads, so reads/writes
    are serialized with a lock and written atomically (temp file + replace).
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional

from . import config

_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def key(params: dict) -> str:
    """
    Stable checkpoint key from the scan's *scope* parameters.

    Account selection is intentionally excluded (units are keyed by account_id
    inside the file). Search terms ARE included — different terms mean different
    matches, so they must not share a checkpoint.
    """
    canonical = {
        "search_terms": sorted(params.get("search_terms") or []),
        "services": sorted(params.get("services") or []),
        "regions": sorted(params.get("regions") or []),
        "management_account": bool(params.get("management_account")),
    }
    blob = json.dumps(canonical, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _path(ck_key: str) -> str:
    return os.path.join(config.CHECKPOINT_DIR, f"{ck_key}.json")


def _read(ck_key: str) -> dict:
    path = _path(ck_key)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _write_atomic(ck_key: str, doc: dict) -> None:
    config.ensure_checkpoint_dir()
    path = _path(ck_key)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2, default=str)
    os.replace(tmp, path)


def get_fresh_units(ck_key: str, ttl_seconds: Optional[int] = None) -> dict:
    """
    Return the unit records that are still fresh (within TTL), keyed by unit id.

    Stale units are omitted so they get re-scanned. Returns ``{}`` when there is
    no checkpoint.
    """
    ttl = config.CHECKPOINT_TTL_SECONDS if ttl_seconds is None else ttl_seconds
    doc = _read(ck_key)
    units = doc.get("units", {})
    if not units:
        return {}
    now = datetime.now(timezone.utc)
    fresh = {}
    for unit_key, rec in units.items():
        completed_at = rec.get("completed_at")
        try:
            age = (now - datetime.fromisoformat(completed_at)).total_seconds()
        except (TypeError, ValueError):
            continue  # malformed timestamp -> treat as stale
        if age <= ttl:
            fresh[unit_key] = rec
    return fresh


def save_unit(ck_key: str, params: dict, unit_key: str, record: dict) -> None:
    """Merge a single completed unit into the checkpoint file atomically."""
    with _LOCK:
        doc = _read(ck_key)
        if not doc:
            doc = {"params": {
                "search_terms": params.get("search_terms"),
                "services": params.get("services"),
                "regions": params.get("regions"),
                "management_account": bool(params.get("management_account")),
            }, "units": {}}
        doc.setdefault("units", {})[unit_key] = {"completed_at": _now(), **record}
        _write_atomic(ck_key, doc)


def delete(ck_key: str) -> None:
    """Remove a checkpoint file (called after a fully successful scan)."""
    with _LOCK:
        path = _path(ck_key)
        if os.path.exists(path):
            os.remove(path)


# ─── Helpers for the cache overview / clear API ──────────────────────────────

def _list_files() -> list[str]:
    d = config.CHECKPOINT_DIR
    if not os.path.isdir(d):
        return []
    return [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".json")]


def summary() -> dict:
    """Aggregate info about checkpoint files for the cache overview."""
    files = _list_files()
    size = sum(os.path.getsize(f) for f in files)
    newest = None
    if files:
        mtime = max(os.path.getmtime(f) for f in files)
        newest = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
    return {"count": len(files), "size_bytes": size, "newest": newest}


def clear_all() -> int:
    """Delete all checkpoint files. Returns the count removed."""
    with _LOCK:
        files = _list_files()
        for f in files:
            try:
                os.remove(f)
            except OSError:
                pass
        return len(files)
