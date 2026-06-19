"""
Path and location configuration for the Truffle frontend.

Centralizes the on-disk locations so the rest of the backend never has to
guess where things live. Everything is local to the repo per the design
tenets (local machine, local resources, local cache files).
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
