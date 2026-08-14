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
from .aws_session import build_assumed_session, build_session
from .suppressed_logger import SuppressedLogger

_slog = SuppressedLogger("policy_analysis")

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
        params: dict with keys search_terms (required), auth_method
            ("profiles" | "assume_role"), and the inputs for the chosen method:
              * profiles  — list of local credential profiles, OR
              * account_ids + role_name (+ optional assume_from_profile) — a
                list of account IDs and a single role to assume in each.
            Plus regions, services, management_account, workers, account_workers.
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

    _slog.start_job(params.get("_job_id") or "unknown")

    # ── Resolve scan targets from the chosen authentication method ───────────
    # Two mutually-exclusive ways to enumerate the accounts to scan:
    #   * "profiles"     — one local credential profile per account.
    #   * "assume_role"  — a list of account IDs + a single role name assumed in
    #                      each (using the default chain, or an optional base
    #                      profile, to make the AssumeRole call).
    # A target is normalized to a dict the planning loop can act on uniformly.
    auth_method = params.get("auth_method") or "profiles"
    targets: list[dict] = []
    if auth_method == "assume_role":
        account_ids = [a for a in (params.get("account_ids") or []) if a]
        role_name = (params.get("role_name") or "").strip()
        base_profile = params.get("assume_from_profile") or None
        if not role_name:
            raise ValueError("A role name is required for assume-role authentication.")
        if not account_ids:
            raise ValueError("At least one account ID is required for assume-role authentication.")
        for acct in account_ids:
            targets.append({
                "mode": "assume_role",
                "label": acct,
                "account_id": acct,
                "role_name": role_name,
                "base_profile": base_profile,
            })
    else:
        for profile in (params.get("profiles") or [None]):
            targets.append({"mode": "profile", "label": profile or "(default)", "profile": profile})

    regions_list = params.get("regions") or None
    services = params.get("services") or None
    management_account = bool(params.get("management_account"))
    workers = int(params.get("workers", 5))
    account_workers = int(params.get("account_workers", 4))

    # Default region for sessions (used by global service calls like S3 ListBuckets)
    default_region = (regions_list[0] if regions_list else None) or "us-east-1"

    scanner = _load_scanner()
    scanner.MAX_WORKERS = workers
    scanner.reset_skipped_resources()
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

    # ── Phase 1: plan — resolve account_id + regions per target ──────────────
    # Doing this up front gives a stable denominator for the progress bar.
    plan = []  # (label, account_id, session, [(scope, region), ...])
    per_profile: list[dict] = []

    # For assume_role mode, resolve the base credentials' account once so we can
    # skip AssumeRole when a target account is the same as the caller account.
    # This avoids the common failure of trying to assume a role in your own
    # account which may not be configured for self-assumption.
    _base_account_id: Optional[str] = None
    _base_session: Optional[object] = None
    if auth_method == "assume_role":
        try:
            _base_session = build_session(targets[0].get("base_profile") if targets else None, region=default_region)
            _base_account_id = _base_session.client("sts").get_caller_identity()["Account"]  # type: ignore[union-attr]
        except Exception as exc:
            _slog.record(exc, context="resolve_base_session_for_assume_role")
            _base_account_id = None
            _base_session = None

    for tgt in targets:
        try:
            if tgt["mode"] == "assume_role":
                # If the target account matches the caller's own account, reuse
                # the base session directly rather than assuming into ourselves.
                if _base_account_id and tgt["account_id"] == _base_account_id and _base_session:
                    session = _base_session  # type: ignore[assignment]
                else:
                    session = build_assumed_session(
                        tgt["account_id"], tgt["role_name"], tgt["base_profile"]
                    )
                account_id = tgt["account_id"]
            else:
                session = build_session(tgt["profile"], region=default_region)
                account_id = session.client("sts").get_caller_identity()["Account"]
            regions = scanner.get_regions(session, regions_arg)
            units = [("global", None)] + [("region", r) for r in regions]
            plan.append((tgt["label"], account_id, session, units))
        except Exception as exc:  # planning failure — account can't be scanned
            per_profile.append({
                "profile": tgt["label"],
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
        label = profile  # already normalized to a display label in the plan
        acct_matches: list[dict] = []
        unit_errors: list[str] = []

        # Resolve the organization ID once per account (best-effort) so we can
        # build proper ARNs for SCP/RCP matches.
        org_id = "o-unknown"
        if management_account:
            try:
                org_id = session.client("organizations").describe_organization()["Organization"]["Id"]
            except Exception as exc:
                _slog.record(exc, context="describe_organization", resource=account_id)
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
                    m["profile"] = label
                    # Ensure every match carries the account_id. The scanner
                    # does not populate this itself.
                    if "account_id" not in m or not m["account_id"]:
                        m["account_id"] = account_id
                    # The Organizations scanner uses a short form like
                    # "SCP:p-abc123" rather than a real ARN. Expand it to
                    # the full Organizations policy ARN.
                    arn = m.get("resource_arn", "")
                    if arn.startswith("SCP:") or arn.startswith("RCP:"):
                        prefix, policy_id = arn.split(":", 1)
                        m["resource_arn"] = (
                            f"arn:aws:organizations::{account_id}:policy/{org_id}/"
                            f"{'service_control_policy' if prefix == 'SCP' else 'resource_control_policy'}"
                            f"/{policy_id}"
                        )
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
            "profile": label,
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

    # Keep per-profile order stable relative to the requested targets.
    order = {t["label"]: i for i, t in enumerate(targets)}
    per_profile.sort(key=lambda e: order.get(e["profile"], len(order)))

    fully_successful = planning_errors == 0 and unit_error_count == 0
    if fully_successful:
        # Deliberate future re-runs should be fresh; nothing left to resume.
        checkpoint.delete(ck_key)

    # Collect resources that were skipped due to API errors during this scan.
    skipped_resources = scanner.get_skipped_resources()

    payload = {
        "search_terms": search_terms,
        "auth_method": auth_method,
        "profiles": [t["label"] for t in targets],
        "per_profile": per_profile,
        "services_filter": services or "all",
        "regions_scanned": sorted(regions_scanned),
        "management_account": management_account,
        "total_matches": len(all_matches),
        "matches": all_matches,
        "skipped_resources": skipped_resources,
        "total_skipped": len(skipped_resources),
        "resume": {
            "total_units": total_units,
            "skipped_units": skipped,
            "resumed": skipped > 0,
            "complete": fully_successful,
        },
        "suppressed_warnings": _slog.get_summary(),
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
