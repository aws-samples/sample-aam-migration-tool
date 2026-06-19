"""
IdC -> AAM feature — SKELETON.

Outlines the workflow from the design doc. No real IdC/SSO-admin calls are made
yet; functions validate inputs, persist to the local cache, and return shapes
the UI can render.

Planned workflow:
  1. User MUST supply a credential profile for the IdC management or delegated
     admin account.
  2. Analysis dumps all permission sets and assignments in a neat format,
     organized by account, for the user to select from.
  3. User selects the permission sets / assignments to migrate.
  4. Tool generates a CloudFormation template with the roles to create.
"""

from typing import Optional

from . import cache, config


def run_discovery(profile: str) -> dict:
    """
    Discover permission sets and assignments (NOT IMPLEMENTED).

    Real behavior will use the IdC / SSO-admin APIs noted in the README
    (ListPermissionSets, GetInlinePolicyForPermissionSet,
    ListCustomerManagedPolicyReferencesInPermissionSet, ListAccountAssignments)
    against the supplied management / delegated-admin ``profile``, then cache a
    structure organized by account.

    For now we persist an empty skeleton so the UI flow is exercisable.
    """
    if not profile:
        raise ValueError("A management or delegated-admin profile is required.")

    payload = {
        "profile": profile,
        # Shape the UI will consume once discovery is implemented:
        # accounts -> [{ account_id, account_name, permission_sets: [...],
        #               assignments: [...] }]
        "accounts": [],
        "permission_sets": [],
        "status": "skeleton",
    }
    return cache.write_cache(config.IDC_CACHE, payload)


def get_state() -> Optional[dict]:
    """Return the cached discovery dump, or ``None``."""
    return cache.read_cache(config.IDC_CACHE)


def generate_cloudformation(selections: dict) -> dict:
    """
    Generate a CloudFormation template of roles to create (NOT IMPLEMENTED).

    ``selections`` will describe the permission sets / assignments (organized
    by account) the user chose to migrate. Real behavior will emit an
    AWS::IAM::Role per selection with equivalent inline/managed/CMP policies,
    permission boundaries, and tags / role paths.
    """
    raise NotImplementedError(
        "CloudFormation generation is not implemented yet. This is a skeleton; "
        "the UI selection flow exists but no template is produced."
    )
