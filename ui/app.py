#!/usr/bin/env python3
"""
Truffle local migration console — Flask entry point.

Serves a JSON API under /api and the built Cloudscape/React UI (from
web/dist) for everything else. Runs locally only; uses the local AWS
credential chain.

Run:
    python3 app.py            # serve API (+ built UI if web/dist exists)

During UI development, run the Vite dev server separately (see
web/README) — it proxies /api here.
"""

import os

from flask import Flask, jsonify, request, send_from_directory

from backend import aws_session, cache, config, iam_federation, idc, jobs, policy_analysis

# The Vite build outputs here. Absent until `npm run build` is run in web/.
WEB_DIST = os.path.join(config.APP_DIR, "web", "dist")

app = Flask(__name__, static_folder=None)


# ─── Shared helpers ──────────────────────────────────────────────────────────

def _json_error(message: str, status: int = 400):
    return jsonify({"error": message}), status


# ─── Meta / credentials ──────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/api/config")
def get_config():
    """Return runtime configuration the UI needs (region, mode, etc.)."""
    return jsonify({
        "idc_region": config.IDC_REGION,
        "execution_mode": config.EXECUTION_MODE,
    })


@app.get("/api/profiles")
def profiles():
    """List named AWS profiles from the local credential chain."""
    return jsonify({"profiles": aws_session.list_profiles()})


@app.get("/api/whoami")
def whoami():
    """Resolve caller identity for a profile (read-only STS call)."""
    profile = request.args.get("profile") or None
    return jsonify(aws_session.whoami(profile))


# ─── Cache management ────────────────────────────────────────────────────────

@app.get("/api/cache")
def cache_overview():
    """Overview of all local cache files (age, size, summary) for the UI."""
    return jsonify(cache.overview())


@app.post("/api/cache/clear")
def cache_clear():
    """Clear one cache file (by key) or all of them when no key is given."""
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(cache.clear(body.get("key")))
    except ValueError as exc:
        return _json_error(str(exc))


# ─── Policy Analysis (wired) ─────────────────────────────────────────────────

@app.get("/api/policy-analysis/services")
def policy_services():
    return jsonify({"services": policy_analysis.list_services()})


@app.get("/api/policy-analysis/result")
def policy_result():
    return jsonify(policy_analysis.get_cached() or {})


@app.post("/api/policy-analysis/scan")
def policy_scan():
    """Start a scan job; returns a job_id to poll for progress and results."""
    body = request.get_json(silent=True) or {}
    search = body.get("search_terms") or []
    if isinstance(search, str):
        search = [t.strip() for t in search.split(",") if t.strip()]
    if not search:
        return _json_error("search_terms is required")
    params = {
        "search_terms": search,
        "auth_method": body.get("auth_method") or "profiles",
        "profiles": body.get("profiles") or None,
        "account_ids": body.get("account_ids") or None,
        "role_name": body.get("role_name") or None,
        "assume_from_profile": body.get("assume_from_profile") or None,
        "regions": body.get("regions") or None,
        "services": body.get("services") or None,
        "management_account": bool(body.get("management_account")),
        "workers": int(body.get("workers", 5)),
        "account_workers": int(body.get("account_workers", 4)),
    }
    job_id = jobs.start_scan(params)
    return jsonify({"job_id": job_id})


@app.get("/api/policy-analysis/status")
def policy_status():
    """Poll a scan job's progress and (when finished) its result."""
    job_id = request.args.get("job_id")
    if not job_id:
        return _json_error("job_id is required")
    job = jobs.get(job_id)
    if job is None:
        # Unknown job — likely the server restarted. The caller can re-run; the
        # scan checkpoint will resume any completed work.
        return _json_error("Unknown job. Re-run to resume from the last checkpoint.", 404)
    # While running, augment with the scanner's fast-moving live activity
    # (current service + resources scanned this run) so the UI shows steady
    # movement between the coarser per-unit progress ticks.
    if job.get("status") == "running" and job.get("type") == "policy-scan":
        snap = policy_analysis.live_snapshot()
        baseline = job["progress"].get("resource_baseline", snap["resource_count_total"])
        job["progress"] = {
            **job["progress"],
            "activity": snap["activity"],
            "resources": max(0, snap["resource_count_total"] - baseline),
        }
    return jsonify(job)


# ─── IAM Federation -> AAM (wired) ───────────────────────────────────────────

@app.post("/api/iam-federation/providers")
def iam_providers():
    """List SAML providers across target accounts."""
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(iam_federation.list_providers(body))
    except Exception as exc:
        return _json_error(str(exc), 500)


@app.post("/api/iam-federation/discover")
def iam_discover():
    """Start a role discovery job; returns a job_id to poll."""
    body = request.get_json(silent=True) or {}
    if not body.get("idp_filter") and not body.get("idp_arn"):
        return _json_error("idp_filter or idp_arn is required")
    job_id = jobs.start_iam_discover(body)
    return jsonify({"job_id": job_id})


@app.get("/api/iam-federation/discover/status")
def iam_discover_status():
    """Poll a discovery job's progress."""
    job_id = request.args.get("job_id")
    if not job_id:
        return _json_error("job_id is required")
    job = jobs.get(job_id)
    if job is None:
        return _json_error("Unknown job.", 404)
    return jsonify(job)


@app.get("/api/iam-federation/state")
def iam_state():
    """Return cached discovery results."""
    return jsonify(iam_federation.get_state() or {})


@app.post("/api/iam-federation/migrate")
def iam_migrate():
    """Migrate selected roles — update trust policies."""
    body = request.get_json(silent=True) or {}
    role_arns = body.get("role_arns") or []
    if not role_arns:
        return _json_error("role_arns is required")
    try:
        result = iam_federation.migrate_roles(body)
        return jsonify(result)
    except Exception as exc:
        return _json_error(str(exc), 500)


@app.post("/api/iam-federation/generate-iac")
def iam_generate_iac():
    """Generate CloudFormation + Terraform templates from cached discovery."""
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(iam_federation.generate_iac(body))
    except Exception as exc:
        return _json_error(str(exc), 500)


@app.get("/api/iam-federation/log")
def iam_log():
    """Return the migration log (per-role success/failure)."""
    return jsonify(iam_federation.get_migration_log() or {})


# ─── IdC -> AAM (wired) ──────────────────────────────────────────────────────

@app.get("/api/idc/state")
def idc_state():
    """Return cached inventory results."""
    return jsonify(idc.get_state() or {})


@app.post("/api/idc/discover")
def idc_discover():
    """Start an IdC inventory job; returns a job_id to poll."""
    body = request.get_json(silent=True) or {}
    try:
        job_id = jobs.start_idc_discover(body)
    except Exception as exc:
        return _json_error(str(exc), 502)
    return jsonify({"job_id": job_id})


@app.get("/api/idc/discover/status")
def idc_discover_status():
    """Poll an IdC discovery job's progress."""
    job_id = request.args.get("job_id")
    if not job_id:
        return _json_error("job_id is required")
    job = jobs.get(job_id)
    if job is None:
        return _json_error("Unknown job.", 404)
    return jsonify(job)


@app.post("/api/idc/generate-iac")
def idc_generate_iac():
    """Generate CloudFormation template(s) from cached inventory."""
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(idc.generate_iac(body))
    except Exception as exc:  # noqa: BLE001
        return _json_error(str(exc), 500)


@app.post("/api/idc/apply")
def idc_apply():
    """Start a job to create roles + entitlements directly via API."""
    body = request.get_json(silent=True) or {}
    job_id = jobs.start_idc_apply(body)
    return jsonify({"job_id": job_id})


@app.get("/api/idc/apply/status")
def idc_apply_status():
    """Poll an IdC apply job's progress."""
    job_id = request.args.get("job_id")
    if not job_id:
        return _json_error("job_id is required")
    job = jobs.get(job_id)
    if job is None:
        return _json_error("Unknown job.", 404)
    return jsonify(job)


# ─── Static UI (built React app) ─────────────────────────────────────────────

@app.get("/", defaults={"path": ""})
@app.get("/<path:path>")
def serve_frontend(path: str):
    """Serve the built SPA, falling back to index.html for client routing."""
    if not os.path.isdir(WEB_DIST):
        return (
            "<h1>Truffle backend is running.</h1>"
            "<p>The UI has not been built yet. From <code>ui/web</code> run "
            "<code>npm install</code> then <code>npm run dev</code> (development) "
            "or <code>npm run build</code> (to serve from here).</p>",
            200,
        )
    target = os.path.join(WEB_DIST, path)
    if path and os.path.isfile(target):
        return send_from_directory(WEB_DIST, path)
    return send_from_directory(WEB_DIST, "index.html")


if __name__ == "__main__":
    config.ensure_cache_dir()
    app.run(host="127.0.0.1", port=5000, debug=False)
