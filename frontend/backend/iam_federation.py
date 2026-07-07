"""
IAM Federation → AAM feature — WIRED adapter.

Thin wrapper over ``IAM Federation to AAM/AAM_role_evaluation.py``. It adapts
the CLI-oriented script into functions the Flask API can call, handling:

  * credential resolution (single/multi account, profiles vs assume-role),
  * SAML provider listing,
  * federated role discovery and caching,
  * trust policy migration (ADD / REPLACE) with per-role logging,
  * IaC template generation (CloudFormation + Terraform).

Results and logs are cached to local JSON files per the design tenets.
"""

import importlib.util
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from threading import Lock
from typing import Callable, Optional

from . import cache, config
from .aws_session import build_assumed_session, build_session

# ─── Load the evaluation script by path ──────────────────────────────────────

_SCRIPT_DIR = os.path.join(config.REPO_ROOT, "IAM Federation to AAM")
_EVAL_PATH = os.path.join(_SCRIPT_DIR, "AAM_role_evaluation.py")
_IAC_PATH = os.path.join(_SCRIPT_DIR, "generate_iac_templates.py")

ProgressCb = Callable[[dict], None]

MAX_WORKERS = 5


def _load_eval():
    spec = importlib.util.spec_from_file_location("AAM_role_evaluation", _EVAL_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load evaluation script from {_EVAL_PATH}")
    module = sys.modules.get("AAM_role_evaluation")
    if module is None:
        module = importlib.util.module_from_spec(spec)
        sys.modules["AAM_role_evaluation"] = module
        spec.loader.exec_module(module)
    return module


def _load_iac():
    spec = importlib.util.spec_from_file_location("generate_iac_templates", _IAC_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load IaC generator from {_IAC_PATH}")
    module = sys.modules.get("generate_iac_templates")
    if module is None:
        module = importlib.util.module_from_spec(spec)
        sys.modules["generate_iac_templates"] = module
        spec.loader.exec_module(module)
    return module


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── Credential helpers ──────────────────────────────────────────────────────

def _resolve_sessions(params: dict) -> list[tuple[str, "boto3.Session", str]]:
    """
    Resolve boto3 sessions from the auth params.

    Returns a list of (label, session, account_id) tuples.
    """
    import boto3  # noqa: F811 — late import to avoid top-level dependency

    auth_method = params.get("auth_method") or "profiles"

    if auth_method == "assume_role":
        account_ids = [a for a in (params.get("account_ids") or []) if a]
        role_name = (params.get("role_name") or "").strip()
        base_profile = params.get("assume_from_profile") or None

        # Resolve base account to skip self-assumption
        base_session = build_session(base_profile)
        base_account = base_session.client("sts").get_caller_identity()["Account"]

        results = []
        for acct in account_ids:
            if acct == base_account:
                results.append((acct, base_session, acct))
            else:
                session = build_assumed_session(acct, role_name, base_profile)
                results.append((acct, session, acct))
        return results
    else:
        profiles = params.get("profiles") or [None]
        results = []
        for profile in profiles:
            session = build_session(profile)
            account_id = session.client("sts").get_caller_identity()["Account"]
            results.append((profile or "(default)", session, account_id))
        return results


# ─── Step 1: List SAML providers ─────────────────────────────────────────────

def list_providers(params: dict) -> dict:
    """
    List SAML identity providers across the target account(s).

    Returns a flat list of providers with account context.
    """
    sessions = _resolve_sessions(params)
    all_providers = []

    for label, session, account_id in sessions:
        iam = session.client("iam")
        response = iam.list_saml_providers()
        for p in response.get("SAMLProviderList", []):
            arn = p["Arn"]
            name = arn.split("/")[-1]
            is_idc = "AWSSSO" in name or "DO_NOT_DELETE" in name
            all_providers.append({
                "arn": arn,
                "name": name,
                "account_id": account_id,
                "label": label,
                "is_identity_center": is_idc,
            })

    return {"providers": all_providers}


# ─── Step 2: Discover federated roles ────────────────────────────────────────

def discover_roles(params: dict, on_progress: Optional[ProgressCb] = None) -> dict:
    """
    Discover IAM roles with SAML trust policies referencing the selected IDP.

    Args:
        params: dict with auth fields + idp_arn (required).
        on_progress: optional callback for progress updates.

    Returns:
        The cache wrapper dict written to disk.
    """
    idp_arn = params.get("idp_arn")
    if not idp_arn:
        raise ValueError("idp_arn is required")

    eval_mod = _load_eval()
    sessions = _resolve_sessions(params)

    all_roles: list[dict] = []
    total_accounts = len(sessions)
    completed = 0
    roles_scanned = 0
    roles_total = 0

    def emit(msg: str, activity: str = ""):
        if on_progress:
            on_progress({
                "completed_units": completed,
                "total_units": total_accounts,
                "skipped_units": 0,
                "message": msg,
                "activity": activity,
                "roles_scanned": roles_scanned,
                "roles_total": roles_total,
            })

    emit(f"Discovering roles across {total_accounts} account(s)")

    for label, session, account_id in sessions:
        try:
            # Temporarily override the module's client/resource with our session
            iam_client = session.client("iam")
            iam_resource = session.resource("iam")

            # Get all role names
            role_names = []
            paginator = iam_client.get_paginator("list_roles")
            for page in paginator.paginate():
                role_names.extend(r["RoleName"] for r in page["Roles"])

            roles_total += len(role_names)
            emit(f"Scanning {len(role_names)} roles in {label} ({account_id})", f"Listing roles in {account_id}")

            # Filter to SAML-federated roles (parallel)
            _scan_lock = Lock()

            def inspect_role(rn: str) -> Optional[dict]:
                nonlocal roles_scanned
                r = iam_resource.Role(rn)
                trust_doc = r.assume_role_policy_document
                if not trust_doc:
                    return None

                for stmt in trust_doc.get("Statement", []):
                    principal = stmt.get("Principal", {})
                    federated = principal.get("Federated", "")
                    if isinstance(federated, str):
                        federated = [federated]
                    if idp_arn in federated:
                        attached = []
                        att_paginator = iam_client.get_paginator("list_attached_role_policies")
                        for att_page in att_paginator.paginate(RoleName=rn):
                            for p in att_page.get("AttachedPolicies", []):
                                policy_type = (
                                    "AWS Managed"
                                    if p["PolicyArn"].startswith("arn:aws:iam::aws:policy")
                                    else "Customer Managed"
                                )
                                attached.append({
                                    "policy_name": p["PolicyName"],
                                    "policy_arn": p["PolicyArn"],
                                    "policy_type": policy_type,
                                })

                        inline = []
                        inl_paginator = iam_client.get_paginator("list_role_policies")
                        for inl_page in inl_paginator.paginate(RoleName=rn):
                            for pname in inl_page.get("PolicyNames", []):
                                inline.append({
                                    "policy_name": pname,
                                    "policy_type": "Inline",
                                })

                        trust_summary = []
                        for s in trust_doc.get("Statement", []):
                            fed = s.get("Principal", {}).get("Federated", "")
                            if isinstance(fed, list):
                                fed = ", ".join(fed)
                            if fed:
                                provider_name = fed.split("/")[-1] if "/" in fed else fed
                                trust_summary.append(f"Federated:{provider_name}")

                        return {
                            "role_name": rn,
                            "role_arn": f"arn:aws:iam::{account_id}:role/{rn}",
                            "account_id": account_id,
                            "label": label,
                            "idp_arn": idp_arn,
                            "trust_policy_document": trust_doc,
                            "trust_summary": "; ".join(trust_summary),
                            "policies": attached + inline,
                        }
                return None

            workers = int(params.get("workers", MAX_WORKERS))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(inspect_role, rn): rn for rn in role_names}
                for fut in as_completed(futures):
                    with _scan_lock:
                        roles_scanned += 1
                        if roles_scanned % 10 == 0:
                            emit(f"Scanning roles in {label} ({account_id})", f"Inspected {roles_scanned}/{roles_total} roles")
                    try:
                        result = fut.result()
                        if result:
                            all_roles.append(result)
                    except Exception:
                        pass

        except Exception as exc:
            all_roles.append({
                "role_name": f"ERROR({label})",
                "role_arn": "",
                "account_id": account_id,
                "label": label,
                "error": str(exc),
                "policies": [],
                "trust_summary": "",
            })

        completed += 1
        emit(f"Completed {label} ({account_id})", "")

    payload = {
        "idp_arn": idp_arn,
        "total_roles": len([r for r in all_roles if not r.get("error")]),
        "roles": all_roles,
        "accounts_scanned": total_accounts,
    }
    return cache.write_cache(config.IAM_FEDERATION_CACHE, payload)


# ─── Step 3: Migrate trust policies ──────────────────────────────────────────

# The trust statement the pushed script uses:
NEW_TRUST_STATEMENT = {
    "Sid": "AAMTrustPolicyStatement",
    "Effect": "Allow",
    "Principal": {
        "Service": "account-access-preview.amazonaws.com"
    },
    "Action": [
        "sts:AssumeRole",
        "sts:SetContext"
    ],
}


def migrate_roles(params: dict, on_progress: Optional[ProgressCb] = None) -> dict:
    """
    Update trust policies on selected roles.

    Args:
        params: dict with auth fields + role_arns (list of ARNs to migrate),
                mode ("ADD" or "REPLACE"), idp_arn (for REPLACE mode).
        on_progress: optional callback for progress updates.

    Returns:
        Migration result summary cached to disk.
    """
    role_arns = params.get("role_arns") or []
    mode = (params.get("mode") or "ADD").upper()
    idp_arn = params.get("idp_arn") or ""

    if not role_arns:
        raise ValueError("At least one role_arn is required")
    if mode not in ("ADD", "REPLACE"):
        raise ValueError("mode must be ADD or REPLACE")

    sessions = _resolve_sessions(params)

    # Build a lookup of account_id -> session
    session_map: dict[str, "boto3.Session"] = {}
    for label, session, account_id in sessions:
        session_map[account_id] = session

    results: list[dict] = []
    total = len(role_arns)
    completed = 0

    def emit(msg: str):
        if on_progress:
            on_progress({
                "completed_units": completed,
                "total_units": total,
                "skipped_units": 0,
                "message": msg,
            })

    emit(f"Migrating {total} role(s) in {mode} mode")

    # Load cached discovery to get trust_policy_documents
    cached = cache.read_cache(config.IAM_FEDERATION_CACHE)
    cached_roles = {}
    if cached and cached.get("data"):
        for r in cached["data"].get("roles", []):
            if r.get("role_arn"):
                cached_roles[r["role_arn"]] = r

    _migrate_lock = Lock()
    workers = int(params.get("workers", MAX_WORKERS))

    def migrate_one_role(role_arn: str) -> dict:
        nonlocal completed
        parts = role_arn.split(":")
        account_id = parts[4] if len(parts) >= 5 else ""
        role_name = role_arn.split("/")[-1]

        session = session_map.get(account_id)
        if not session:
            if sessions:
                session = sessions[0][1]
            else:
                return {
                    "role_arn": role_arn,
                    "role_name": role_name,
                    "status": "error",
                    "error": f"No session available for account {account_id}",
                    "timestamp": _now(),
                }

        try:
            iam_cl = session.client("iam")

            role_resp = iam_cl.get_role(RoleName=role_name)
            trust_doc = role_resp["Role"]["AssumeRolePolicyDocument"]

            existing_sids = {s.get("Sid") for s in trust_doc.get("Statement", [])}
            if NEW_TRUST_STATEMENT["Sid"] in existing_sids:
                return {
                    "role_arn": role_arn,
                    "role_name": role_name,
                    "status": "skipped",
                    "reason": "Already has AAM trust statement",
                    "timestamp": _now(),
                }

            if mode == "ADD":
                new_doc = dict(trust_doc)
                new_doc["Statement"] = list(trust_doc["Statement"]) + [NEW_TRUST_STATEMENT]
            else:
                kept = []
                for stmt in trust_doc["Statement"]:
                    federated = stmt.get("Principal", {}).get("Federated", "")
                    if isinstance(federated, str):
                        federated = [federated]
                    if idp_arn not in federated:
                        kept.append(stmt)
                kept.append(NEW_TRUST_STATEMENT)
                new_doc = dict(trust_doc)
                new_doc["Statement"] = kept

            iam_cl.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(new_doc),
            )

            return {
                "role_arn": role_arn,
                "role_name": role_name,
                "status": "success",
                "mode": mode,
                "timestamp": _now(),
                "previous_trust_policy": trust_doc,
            }

        except Exception as exc:
            return {
                "role_arn": role_arn,
                "role_name": role_name,
                "status": "error",
                "error": str(exc),
                "timestamp": _now(),
            }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(migrate_one_role, arn): arn for arn in role_arns}
        for fut in as_completed(futures):
            result = fut.result()
            results.append(result)
            with _migrate_lock:
                completed += 1
                emit(f"{result['status'].title()}: {result['role_name']}")

    # Append to migration log
    log = cache.read_cache(config.IAM_FEDERATION_MIGRATION_LOG)
    existing_entries = []
    if log and log.get("data"):
        existing_entries = log["data"].get("entries", [])
    existing_entries.extend(results)

    log_payload = {
        "entries": existing_entries,
        "last_run": _now(),
        "last_run_summary": {
            "total": total,
            "success": len([r for r in results if r["status"] == "success"]),
            "skipped": len([r for r in results if r["status"] == "skipped"]),
            "error": len([r for r in results if r["status"] == "error"]),
            "mode": mode,
        },
    }
    cache.write_cache(config.IAM_FEDERATION_MIGRATION_LOG, log_payload)

    # ── Phase 2: Create AAM entitlements (if mappings provided) ──────────────
    # Uses the entitlement mappings from the UI's Step 3 (group pattern parsing).
    # Each mapping has: principal (group/user name), account, role (matched to
    # a federated role ARN). We create one entitlement per mapping.
    entitlement_results: list[dict] = []
    aam_application_arn = params.get("aam_application_arn")
    entitlement_mappings = params.get("entitlement_mappings") or []

    if aam_application_arn and entitlement_mappings:
        # IMPORTANT: AAM entitlements live in the hub/management account.
        # Always use default creds (same as discovery), not the apply-specific creds.
        hub_session = build_session(None)

        aam_region = params.get("aam_region") or "us-east-1"
        aam_endpoint_url = f"https://account-access-preview.{aam_region}.api.aws"

        try:
            aam_client = hub_session.client(
                "accountaccess",
                region_name=aam_region,
                endpoint_url=aam_endpoint_url,
            )
        except Exception as exc:
            for m in entitlement_mappings:
                entitlement_results.append({
                    "group": m.get("group", ""),
                    "principal": m.get("principal", ""),
                    "account": m.get("account", ""),
                    "role": m.get("role", ""),
                    "role_arn": m.get("matchedRoleArn", ""),
                    "status": "error",
                    "error": f"AAM client unavailable: {exc}",
                })
            aam_client = None

        if aam_client:
            for m in entitlement_mappings:
                role_arn = m.get("matchedRoleArn", "")
                principal_id = m.get("principal", "")
                # Default to groupId; if user specifies principal_type, honor it
                principal_type = m.get("principal_type", "GROUP")

                if not role_arn:
                    entitlement_results.append({
                        "group": m.get("group", ""),
                        "principal": principal_id,
                        "account": m.get("account", ""),
                        "role": m.get("role", ""),
                        "role_arn": "",
                        "status": "skipped",
                        "error": "No matched role ARN",
                    })
                    continue

                principal_block: dict = {}
                if principal_type == "USER":
                    principal_block["userId"] = principal_id
                else:
                    principal_block["groupId"] = principal_id

                try:
                    resp = aam_client.create_entitlement(
                        applicationArn=aam_application_arn,
                        entitlement={
                            "principalRole": {
                                "principal": {"identityCenter": principal_block},
                                "roleArn": role_arn,
                            }
                        },
                    )
                    entitlement_results.append({
                        "group": m.get("group", ""),
                        "principal": principal_id,
                        "account": m.get("account", ""),
                        "role": m.get("role", ""),
                        "role_arn": role_arn,
                        "entitlement_id": resp.get("entitlementId", ""),
                        "status": "created",
                    })
                except Exception as exc:
                    error_str = str(exc)
                    status = "already exists" if "Conflict" in error_str or "AlreadyExists" in error_str else "error"
                    entitlement_results.append({
                        "group": m.get("group", ""),
                        "principal": principal_id,
                        "account": m.get("account", ""),
                        "role": m.get("role", ""),
                        "role_arn": role_arn,
                        "status": status,
                        "error": error_str if status == "error" else "already exists",
                    })

    return {
        "total": total,
        "results": results,
        "entitlement_results": entitlement_results,
        "summary": {
            **log_payload["last_run_summary"],
            "entitlements_total": len(entitlement_results),
            "entitlements_created": len([e for e in entitlement_results if e["status"] == "created"]),
            "entitlements_error": len([e for e in entitlement_results if e["status"] == "error"]),
        },
    }


# ─── Step 4: Generate IaC templates ──────────────────────────────────────────

def generate_iac(params: dict) -> dict:
    """
    Generate CloudFormation and Terraform templates from the cached discovery.

    Uses the generate_iac_templates module's logic but writes to the cache
    directory rather than the script's directory.
    """
    iac_mod = _load_iac()

    # Build the roles dict from cache (same format as parse_csv returns)
    cached = cache.read_cache(config.IAM_FEDERATION_CACHE)
    if not cached or not cached.get("data"):
        raise ValueError("No discovery data cached. Run discovery first.")

    roles_data = cached["data"].get("roles", [])
    if not roles_data:
        raise ValueError("No roles found in cached discovery.")

    # Filter to only requested roles if specified
    requested_arns = params.get("role_arns")
    if requested_arns:
        roles_data = [r for r in roles_data if r.get("role_arn") in requested_arns]

    # Build the dict format generate_iac_templates expects: {role_name: [policies]}
    roles_dict: dict[str, list[dict]] = {}
    for r in roles_data:
        if r.get("error"):
            continue
        role_name = r["role_name"]
        policies = []
        for p in r.get("policies", []):
            policies.append({
                "policy_name": p["policy_name"],
                "policy_type": p["policy_type"],
            })
        roles_dict[role_name] = policies

    if not roles_dict:
        raise ValueError("No valid roles to generate templates for.")

    # Generate to cache directory
    cfn_path = os.path.join(config.CACHE_DIR, "aam_roles_cloudformation.yaml")
    tf_path = os.path.join(config.CACHE_DIR, "aam_roles_terraform.tf")

    iac_mod.generate_cloudformation(roles_dict, cfn_path)
    iac_mod.generate_terraform(roles_dict, tf_path)

    # Read the generated content to return to the UI
    with open(cfn_path, "r") as f:
        cfn_content = f.read()
    with open(tf_path, "r") as f:
        tf_content = f.read()

    return {
        "roles_count": len(roles_dict),
        "cloudformation": {
            "path": cfn_path,
            "content": cfn_content,
        },
        "terraform": {
            "path": tf_path,
            "content": tf_content,
        },
    }


# ─── Read cached state ───────────────────────────────────────────────────────

def get_state() -> Optional[dict]:
    """Return cached discovery (roles + providers), or None."""
    return cache.read_cache(config.IAM_FEDERATION_CACHE)


def get_migration_log() -> Optional[dict]:
    """Return the migration success/failure log, or None."""
    return cache.read_cache(config.IAM_FEDERATION_MIGRATION_LOG)
