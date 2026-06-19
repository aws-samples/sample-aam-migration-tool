"""
Local-file cache helpers.

The design requires caching resource policy analysis, permission set dumps,
and federation configuration to local files that are referenced on load.
These helpers keep that read/write logic in one place.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

from . import checkpoint, config


def read_cache(path: str) -> Optional[dict]:
    """Return the parsed JSON cache at ``path`` or ``None`` if absent/invalid."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def write_cache(path: str, payload: Any) -> dict:
    """
    Write ``payload`` to ``path`` as JSON, wrapped with metadata.

    Returns the wrapper dict that was written so callers can return it
    directly to the UI.
    """
    config.ensure_cache_dir()
    wrapper = {
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "data": payload,
    }
    with open(path, "w") as f:
        json.dump(wrapper, f, indent=2, default=str)
    return wrapper


def append_log(path: str, entry: dict) -> dict:
    """
    Append a single entry to a JSON-array log file (creating it if needed).

    Used for migration success/failure logging per the design doc.
    """
    config.ensure_cache_dir()
    existing = read_cache(path)
    entries = existing.get("data", []) if existing else []
    entry = {"logged_at": datetime.now(timezone.utc).isoformat(), **entry}
    entries.append(entry)
    return write_cache(path, entries)


def _summarize(data: Any) -> str:
    """Build a short, human-readable summary of a cache file's contents."""
    if data is None:
        return "empty"
    if isinstance(data, list):
        return f"{len(data)} entr{'y' if len(data) == 1 else 'ies'}"
    if isinstance(data, dict):
        if "total_matches" in data:
            profiles = data.get("profiles") or []
            return f"{data['total_matches']} match(es) across {len(profiles)} profile(s)"
        if "accounts" in data or "permission_sets" in data:
            status = data.get("status", "")
            n = len(data.get("accounts") or [])
            return f"{n} account(s){f' — {status}' if status else ''}"
        if "status" in data:
            return str(data["status"])
        return f"{len(data)} field(s)"
    return "present"


def overview() -> dict:
    """
    Return metadata for every known cache file so the UI can show an overview
    and let the user decide what to clear.
    """
    entries = []
    for key, meta in config.CACHE_FILES.items():
        path = meta["path"]
        exists = os.path.exists(path)
        wrapper = read_cache(path) if exists else None
        entries.append({
            "key": key,
            "label": meta["label"],
            "exists": exists,
            "size_bytes": os.path.getsize(path) if exists else 0,
            "cached_at": (wrapper or {}).get("cached_at") if wrapper else None,
            "summary": _summarize((wrapper or {}).get("data")) if wrapper else "not created",
        })

    # Scan checkpoints are dynamic (hash-named), so represent them as one
    # aggregate row.
    ck = checkpoint.summary()
    entries.append({
        "key": "checkpoints",
        "label": "Scan checkpoints (resume data)",
        "exists": ck["count"] > 0,
        "size_bytes": ck["size_bytes"],
        "cached_at": ck["newest"],
        "summary": (
            f"{ck['count']} interrupted scan(s)" if ck["count"] else "none"
        ),
    })
    return {"entries": entries}


def clear(key: Optional[str] = None) -> dict:
    """
    Delete one cache file (by key) or all of them when ``key`` is ``None``.

    The special key ``"checkpoints"`` clears all scan-checkpoint files.
    Returns the list of keys that were actually removed.
    """
    valid = set(config.CACHE_FILES) | {"checkpoints"}
    if key is not None and key not in valid:
        raise ValueError(f"Unknown cache key: {key}")

    targets = [key] if key else list(config.CACHE_FILES.keys()) + ["checkpoints"]
    cleared = []
    for k in targets:
        if k == "checkpoints":
            if checkpoint.clear_all() > 0:
                cleared.append("checkpoints")
            continue
        path = config.CACHE_FILES[k]["path"]
        if os.path.exists(path):
            os.remove(path)
            cleared.append(k)
    return {"cleared": cleared}
