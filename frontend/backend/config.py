"""
Path and location configuration for the Truffle frontend.

Centralizes the on-disk locations so the rest of the backend never has to
guess where things live. Everything is local to the repo per the design
tenets (local machine, local resources, local cache files).

Execution mode:
  TRUFFLE_MODE=local    (default) — scan/discover/migrate run in-process
  TRUFFLE_MODE=managed  — jobs are submitted to the managed AWS backend
"""

import os

# frontend/backend/config.py -> frontend/ -> repo root
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.dirname(BACKEND_DIR)
REPO_ROOT = os.path.dirname(FRONTEND_DIR)

# Existing utilities we reuse.
UTILITIES_DIR = os.path.join(REPO_ROOT, "Utilites")
RESOURCE_POLICY_SCAN_DIR = os.path.join(UTILITIES_DIR, "resource_policy_scan")

# Local cache directory. Results are written here and re-read on load so the
# UI can show prior runs without re-hitting AWS.
CACHE_DIR = os.path.join(FRONTEND_DIR, "cache")

# Named cache files per feature.
POLICY_ANALYSIS_CACHE = os.path.join(CACHE_DIR, "policy_analysis.json")
IAM_FEDERATION_CACHE = os.path.join(CACHE_DIR, "iam_federation.json")
IDC_CACHE = os.path.join(CACHE_DIR, "idc.json")

# Migration result logs (success/failure per resource), per the design doc.
IAM_FEDERATION_MIGRATION_LOG = os.path.join(CACHE_DIR, "iam_federation_migration_log.json")
IDC_MIGRATION_LOG = os.path.join(CACHE_DIR, "idc_migration_log.json")

# Registry of all known cache files, keyed by a stable id used by the cache
# overview / clear API. Keeping this in one place lets the UI render a complete
# picture of what is cached so the user can decide what to clear.
CACHE_FILES = {
    "policy_analysis": {"label": "Policy Analysis — scan results", "path": POLICY_ANALYSIS_CACHE},
    "iam_federation": {"label": "IAM Federation — entitlements / roles", "path": IAM_FEDERATION_CACHE},
    "iam_federation_migration_log": {"label": "IAM Federation — migration log", "path": IAM_FEDERATION_MIGRATION_LOG},
    "idc": {"label": "IdC — discovery dump", "path": IDC_CACHE},
    "idc_migration_log": {"label": "IdC — migration log", "path": IDC_MIGRATION_LOG},
}


def ensure_cache_dir() -> str:
    """Create the cache directory if it does not already exist."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    return CACHE_DIR


# ─── Scan checkpoints (resume support) ───────────────────────────────────────
# Completed scan units (per account/region) are checkpointed here so an
# interrupted scan can resume without re-doing finished work. Files are named
# by a hash of the scan parameters.
CHECKPOINT_DIR = os.path.join(CACHE_DIR, "checkpoints")

# Checkpoint units older than this are considered stale and re-scanned, so a
# resumed scan never silently serves very old data.
CHECKPOINT_TTL_SECONDS = 24 * 3600


def ensure_checkpoint_dir() -> str:
    """Create the checkpoint directory if it does not already exist."""
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    return CHECKPOINT_DIR


# ─── Execution mode (local vs managed backend) ───────────────────────────────
# Set TRUFFLE_MODE=managed and TRUFFLE_API_ENDPOINT to the API Gateway URL to
# route jobs to the managed serverless backend instead of running locally.

EXECUTION_MODE = os.environ.get("TRUFFLE_MODE", "local")  # "local" | "managed"
API_ENDPOINT = os.environ.get("TRUFFLE_API_ENDPOINT", "")  # e.g. https://<id>.execute-api.<region>.amazonaws.com/prod
API_PROFILE = os.environ.get("TRUFFLE_API_PROFILE", "")  # optional: AWS profile for signing


def _parse_region_from_endpoint(endpoint: str) -> str:
    """Extract the AWS region from an API Gateway endpoint URL.

    Expected format: https://<id>.execute-api.<region>.amazonaws.com/...
    Falls back to us-west-2 if parsing fails.
    """
    try:
        # e.g. "https://abc123.execute-api.us-west-2.amazonaws.com/prod"
        host = endpoint.split("//")[-1].split("/")[0]  # abc123.execute-api.us-west-2.amazonaws.com
        parts = host.split(".")
        # parts: [id, "execute-api", region, "amazonaws", "com"]
        if "execute-api" in parts:
            idx = parts.index("execute-api")
            return parts[idx + 1]
    except (IndexError, ValueError):
        pass
    return "us-west-2"


API_REGION = os.environ.get("TRUFFLE_API_REGION") or _parse_region_from_endpoint(API_ENDPOINT)


def is_managed_mode() -> bool:
    """Return True if the backend is configured to use the managed API."""
    return EXECUTION_MODE.lower() == "managed" and bool(API_ENDPOINT)


# ─── IdC / AAM region ────────────────────────────────────────────────────────
# The region where Identity Center and AAM are configured. Passed at launch
# via --region or TRUFFLE_IDC_REGION. Used for Identity Store resolution,
# SSO Admin API calls, and AAM entitlement creation.

IDC_REGION = os.environ.get("TRUFFLE_IDC_REGION", "")
