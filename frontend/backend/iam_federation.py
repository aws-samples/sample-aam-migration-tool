"""
IAM Federation -> AAM feature — SKELETON.

Outlines the workflow from the design doc. None of these perform real AWS
mutations yet; they validate inputs, persist to the local cache, and return
shapes the UI can render. Real implementation is intentionally deferred.

Planned workflow:
  1. User supplies the input entitlements/assignments for the account(s) being
     migrated -> stored and viewable in the UI.
  2. User selects which federated roles to migrate.
  3. Migration updates each role's trust policy by adding the sts:AssumeRole
     statement for the AAM service principal.
  4. On success/failure, append a per-role result to the migration log.
"""

from typing import Optional

from . import cache, config

# Placeholder for the AAM service principal that will be added to trust
# policies during migration. Confirm the real value before implementing.
AAM_SERVICE_PRINCIPAL = "account-access-manager.amazonaws.com"  # TODO: confirm


def import_entitlements(entitlements: dict) -> dict:
    """
    Persist the user-provided entitlements/assignments so they are viewable.

    ``entitlements`` is the raw structure the user uploads/pastes. Validation
    and normalization are TODO; for now we store it verbatim.
    """
    payload = {
        "entitlements": entitlements,
        # Discovery of federated roles from the entitlements is not implemented.
        "federated_roles": [],
        "status": "skeleton",
    }
    return cache.write_cache(config.IAM_FEDERATION_CACHE, payload)


def get_state() -> Optional[dict]:
    """Return cached entitlements / discovered roles, or ``None``."""
    return cache.read_cache(config.IAM_FEDERATION_CACHE)


def migrate_roles(role_arns: list[str], profile: Optional[str] = None) -> dict:
    """
    Migrate the selected federated roles (NOT IMPLEMENTED).

    Real behavior will, per role, add the AAM sts:AssumeRole statement to the
    trust policy and append a success/failure entry to the migration log.
    """
    raise NotImplementedError(
        "Trust-policy migration is not implemented yet. This is a skeleton; "
        "the UI flow exists but no AWS mutations are performed."
    )


def get_migration_log() -> Optional[dict]:
    """Return the migration success/failure log, or ``None``."""
    return cache.read_cache(config.IAM_FEDERATION_MIGRATION_LOG)
