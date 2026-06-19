"""
Policy Analysis feature — WIRED to the existing resource-policy scanner.

This module is a thin adapter over ``Utilites/resource_policy_scan/
scan_resource_policies.py``. It lets the UI:

  * list the services the scanner knows how to inspect,
  * scope a run to one or more local credential profiles (each treated as an
    account, using that profile's resolved credentials),
  * scope by service and region,
  * run scans as resumable, progress-reporting jobs,
  * read back the most recent cached result.

The scan is decomposed into units — one "global" unit per account plus one unit
per (account, region) — which are scanned with accounts in parallel. Each
completed unit is checkpointed (see ``checkpoint.py``) so an interrupted scan
can resume without re-doing finished work. Results are cached to a local file
and re-read on load.
"""

import importlib.util
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from threading import Lock
from typing import Callable, Optional

from . import cache, checkpoint, config
from .aws_session import build_session

# ─── Import the existing scanner module by path ──────────────────────────────
# It lives outside this package, so load it explicitly rather than via a normal
# import. This keeps the scanner as the single source of truth for scan logic.

_SCANNER_PATH = os.path.join(config.RESOURCE_POLICY_SCAN_DIR, "scan_resource_policies.py")

ProgressCb = Callable[[dict], None]


def _load_scanner():
    spec = importlib.util.spec_from_file_location("scan_resource_policies", _SCANNER_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load scanner from {_SCANNER_PATH}")
    module = sys.modules.get("scan_resource_policies")
    if module is None:
        module = importlib.util.module_from_spec(spec)
        sys.modules["scan_resource_policies"] = module
        spec.loader.exec_module(module)
    return module


def list_services() -> list[str]:
    """Return every service name the scanner can inspect (global + regional)."""
    scanner = _load_scanner()
    names = [name for name, _ in scanner.GLOBAL_SCANNERS]
    names += [name for name, _ in scanner.REGIONAL_SCANNERS]
    seen = set()
    unique = []
    for n in names:
        if n not in seen:
            seen.add(n)
            unique.append(n)
    return unique


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_scan_job(params: dict, on_progress: Optional[ProgressCb] = None) -> dict:
    """
    Run a resumable, progress-reporting resource-policy scan.

    Args:
        params: dict with keys search_terms (required), profiles, regions,
            services, management_account, workers, account_workers.
        on_progress: optional callback invoked with progress snapshots
            ({completed_units, total_units, skipped_units, message, ...}).

    Returns:
        The cache wrapper dict ({cached_at, data}) written to disk.

    Resume: completed units are checkpointed keyed by the scope parameters.
    A re-run with the same parameters skips fresh units. The checkpoint is
    deleted only after a fully successful run (no unit or account errors), so a
    deliberate re-run after success starts fresh while an interrupted one
    resumes.
    """
    search_terms = params.get("search_terms") or []
    if not search_terms:
        raise ValueError("At least one search term is required.")

    profiles = params.get("profiles") or [None]
    regions_list = params.get("regions") or None
    services = params.get("services") or None
    management_account = bool(params.get("management_account"))
    workers = int(params.get("workers", 5))
    account_workers = int(params.get("account_workers", 4))

    scanner = _load_scanner()
    scanner.MAX_WORKERS = workers
    regions_arg = ",".join(regions_list) if regions_list else None
    service_filter = {s.strip().lower() for s in services} if services else None

    # Baseline for the scanner's global resource counter so we can report
    # "resources scanned this run" (the counter is process-cumulative).
    resource_baseline = int(getattr(scanner, "_resource_count", 0) or 0)
    if on_progress:
        on_progress({"resource_baseline": resource_baseline, "activity": "starting", "resources": 0})

    ck_key = checkpoint.key(params)
    fresh_units = checkpoint.get_fresh_units(ck_key)

    def emit(msg: str):
        if on_progress:
            with _lock:
                on_progress({
                    "completed_units": completed,
                    "total_units": total_units,
                    "skipped_units": skipped,
                    "message": msg,
                })

    # ── Phase 1: plan — resolve account_id + regions per profile ─────────────
    # Doing this up front gives a stable denominator for the progress bar.
    plan = []  # (profile, account_id, session, [(scope, region), ...])
    per_profile: list[dict] = []
    for profile in profiles:
        try:
            session = build_session(profile)
            account_id = session.client("sts").get_caller_identity()["Account"]
            regions = scanner.get_regions(session, regions_arg)
            units = [("global", None)] + [("region", r) for r in regions]
            plan.append((profile, account_id, session, units))
        except Exception as exc:  # planning failure — account can't be scanned
            per_profile.append({
                "profile": profile or "(default)",
                "status": "error",
                "error": str(exc),
            })

    total_units = sum(len(units) for _, _, _, units in plan)
    completed = 0
    skipped = 0
    _lock = Lock()
    all_matches: list[dict] = []
    regions_scanned: set[str] = set()
    planning_errors = len(per_profile)

    if on_progress:
        on_progress({
            "completed_units": 0,
            "total_units": total_units,
            "skipped_units": 0,
            "message": f"Planned {total_units} unit(s) across {len(plan)} account(s)",
        })

    # ── Phase 2: scan units, accounts in parallel ────────────────────────────
    def scan_one_account(profile, account_id, session, units) -> dict:
        nonlocal completed, skipped
        acct_matches: list[dict] = []
        unit_errors: list[str] = []
        for scope, region in units:
            if scope == "global":
                unit_key = f"{account_id}::global"
            else:
                unit_key = f"{account_id}::region::{region}"

            cached_unit = fresh_units.get(unit_key)
            if cached_unit is not None:
                # Resume: reuse the checkpointed matches, don't re-scan.
                with _lock:
                    completed += 1
                    skipped += 1
                    acct_matches.extend(cached_unit.get("matches", []))
                    if region:
                        regions_scanned.add(region)
                emit(f"Skipped {unit_key} (resumed)")
                continue

            try:
                if scope == "global":
                    matches = scanner.scan_global_services(
                        session, account_id, search_terms, management_account,
                        service_filter, set(),
                    )
                else:
                    matches = scanner.scan_regional_services(
                        session, region, account_id, search_terms,
                        service_filter, set(),
                    )
                for m in matches:
                    m["profile"] = profile or "(default)"
                # Checkpoint this completed unit before moving on.
                checkpoint.save_unit(ck_key, params, unit_key, {
                    "account_id": account_id,
                    "scope": scope,
                    "region": region,
                    "matches": matches,
                })
                with _lock:
                    completed += 1
                    acct_matches.extend(matches)
                    if region:
                        regions_scanned.add(region)
                emit(f"Scanned {unit_key}")
            except Exception as exc:  # unit failure — leave un-checkpointed to retry
                unit_errors.append(f"{unit_key}: {exc}")
                with _lock:
                    completed += 1
                emit(f"Failed {unit_key}")
        return {
            "profile": profile or "(default)",
            "account_id": account_id,
            "matches": acct_matches,
            "errors": unit_errors,
        }

    max_parallel = max(1, min(account_workers, len(plan) or 1))
    unit_error_count = 0
    if plan:
        with ThreadPoolExecutor(max_workers=max_parallel) as pool:
            futures = [pool.submit(scan_one_account, *p) for p in plan]
            for future in as_completed(futures):
                res = future.result()
                all_matches.extend(res["matches"])
                entry = {
                    "profile": res["profile"],
                    "account_id": res["account_id"],
                    "matches": len(res["matches"]),
                    "status": "partial" if res["errors"] else "ok",
                }
                if res["errors"]:
                    entry["errors"] = res["errors"]
                    unit_error_count += len(res["errors"])
                per_profile.append(entry)

    # Keep per-profile order stable relative to the requested profiles.
    order = {(p or "(default)"): i for i, p in enumerate(profiles)}
    per_profile.sort(key=lambda e: order.get(e["profile"], len(order)))

    fully_successful = planning_errors == 0 and unit_error_count == 0
    if fully_successful:
        # Deliberate future re-runs should be fresh; nothing left to resume.
        checkpoint.delete(ck_key)

    payload = {
        "search_terms": search_terms,
        "profiles": [p or "(default)" for p in profiles],
        "per_profile": per_profile,
        "services_filter": services or "all",
        "regions_scanned": sorted(regions_scanned),
        "management_account": management_account,
        "total_matches": len(all_matches),
        "matches": all_matches,
        "resume": {
            "total_units": total_units,
            "skipped_units": skipped,
            "resumed": skipped > 0,
            "complete": fully_successful,
        },
    }
    return cache.write_cache(config.POLICY_ANALYSIS_CACHE, payload)


def get_cached() -> Optional[dict]:
    """Return the most recent cached scan result, or ``None``."""
    return cache.read_cache(config.POLICY_ANALYSIS_CACHE)


def live_snapshot() -> dict:
    """
    Read the scanner's live progress globals for a running scan.

    These are updated continuously (per service / per resource) by the scanner,
    so they give a fast-moving "what's happening now" signal between the
    coarser per-unit progress ticks. With parallel accounts the label is
    last-writer-wins (fuzzy by design); the resource count is cumulative.
    """
    scanner = _load_scanner()
    state = getattr(scanner, "_progress_state", {}) or {}
    return {
        "activity": state.get("label") or "",
        "resource_count_total": int(getattr(scanner, "_resource_count", 0) or 0),
    }
