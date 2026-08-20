"""
IdC → AAM feature — WIRED adapter.

Thin wrapper over ``Identity Center to AAM/`` scripts. Adapts the CLI tool
into functions the Flask API can call, handling:

  * credential resolution (single/multi/org operating modes),
  * IdC inventory (permission sets + assignments) with progress reporting,
  * migration plan generation,
  * IaC template generation (CloudFormation with roles + entitlements),
  * caching results locally per the design tenets.
"""

import importlib.util
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from threading import Lock
from typing import Callable, Optional

from . import cache, config
from .aws_session import build_assumed_session, build_session
from .suppressed_logger import SuppressedLogger

_slog = SuppressedLogger("idc")

# ─── Import the IdC tool modules by path ─────────────────────────────────────

_IDC_DIR = os.path.join(config.REPO_ROOT, "Identity Center to AAM")
_LIB_PATH = os.path.join(_IDC_DIR, "lib.py")

ProgressCb = Callable[[dict], None]

# Default concurrency for parallel operations.
MAX_WORKERS = 5


def _load_idc_lib():
    """Load the shared IdC library module."""
    spec = importlib.util.spec_from_file_location("idc_lib", _LIB_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load IdC lib from {_LIB_PATH}")
    module = sys.modules.get("idc_lib")
    if module is None:
        module = importlib.util.module_from_spec(spec)
        sys.modules["idc_lib"] = module
        spec.loader.exec_module(module)
    return module


def _add_idc_to_path():
    """Ensure the IdC tool directory is importable."""
    if _IDC_DIR not in sys.path:
        sys.path.insert(0, _IDC_DIR)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── Credential/session helpers ──────────────────────────────────────────────

def _resolve_hub_session(params: dict):
    """Build a session for the hub (IdC management) account."""
    auth_method = params.get("auth_method") or "profiles"
    if auth_method == "assume_role":
        # For assume_role, the first account is the hub
        account_ids = [a for a in (params.get("account_ids") or []) if a]
        role_name = (params.get("role_name") or "").strip()
        if account_ids and role_name:
            base_session = build_session(None)
            base_account = base_session.client("sts").get_caller_identity()["Account"]
            if account_ids[0] == base_account:
                return base_session
            return build_assumed_session(account_ids[0], role_name)
        return build_session(None)
    else:
        profiles = params.get("profiles") or [None]
        profile = params.get("profile") or (profiles[0] if profiles else None)
        return build_session(profile)


# ─── Run inventory (job-based) ───────────────────────────────────────────────

def run_inventory(params: dict, on_progress: Optional[ProgressCb] = None) -> dict:
    """
    Run the IdC inventory phase: discover permission sets and assignments.

    Supports three account scopes:
      - "single": only the current account (uses ListPermissionSetsProvisionedToAccount)
      - "multi": specific account IDs (same optimized query per account)
      - "org": all accounts (full ListPermissionSets scan)

    Args:
        params: dict with auth fields + account_scope, target_account_ids (for multi),
                region (IdC primary region).
        on_progress: optional progress callback.

    Returns:
        Cache wrapper dict written to disk.
    """
    _slog.start_job(params.get("_job_id") or "unknown")
    _add_idc_to_path()

    account_scope = params.get("account_scope") or "single"
    region = params.get("region") or "us-east-1"

    session = _resolve_hub_session(params)
    account_id = session.client("sts").get_caller_identity()["Account"]

    from botocore.config import Config as BotoConfig
    boto_cfg = BotoConfig(retries={"mode": "adaptive", "max_attempts": 5}, max_pool_connections=10)

    sso_admin = session.client("sso-admin", region_name=region, config=boto_cfg)
    identity_store = session.client("identitystore", region_name=region, config=boto_cfg)

    # ── Discover IdC instance ────────────────────────────────────────────────
    def emit(msg: str, **kwargs):
        if on_progress:
            on_progress({"message": msg, **kwargs})

    emit("Discovering IdC instance")
    instances = []
    paginator = sso_admin.get_paginator("list_instances")
    for page in paginator.paginate():
        instances.extend(page.get("Instances", []))

    if not instances:
        raise RuntimeError("No IAM Identity Center instance found in this account")

    instance_arn = instances[0]["InstanceArn"]
    identity_store_id = instances[0]["IdentityStoreId"]

    # ── Determine target accounts ────────────────────────────────────────────
    if account_scope == "single":
        target_accounts = [a for a in (params.get("target_account_ids") or []) if a]
        if not target_accounts:
            # Fallback to hub account if no explicit ID provided (CLI usage)
            target_accounts = [account_id]
    elif account_scope == "multi":
        target_accounts = [a for a in (params.get("target_account_ids") or params.get("account_ids") or []) if a]
        if not target_accounts:
            raise ValueError("target_account_ids is required for multi-account scope")
    else:
        target_accounts = None  # org mode — will query all

    # ── List permission sets ─────────────────────────────────────────────────
    if target_accounts is not None:
        # Optimized: ListPermissionSetsProvisionedToAccount per target
        ps_arns_set: set = set()
        for i, acct in enumerate(target_accounts):
            emit(f"Listing permission sets for account {acct}", completed_units=i, total_units=len(target_accounts))
            try:
                pag = sso_admin.get_paginator("list_permission_sets_provisioned_to_account")
                for page in pag.paginate(InstanceArn=instance_arn, AccountId=acct):
                    ps_arns_set.update(page.get("PermissionSets", []))
            except Exception as exc:
                emit(f"Error listing permission sets for {acct}: {exc}")
        ps_arns = sorted(ps_arns_set)
        emit(f"Found {len(ps_arns)} permission set(s) across {len(target_accounts)} account(s)",
             completed_units=len(target_accounts), total_units=len(target_accounts))
    else:
        # Org mode: list all
        emit("Listing all permission sets (org mode)")
        ps_arns = []
        pag = sso_admin.get_paginator("list_permission_sets")
        for page in pag.paginate(InstanceArn=instance_arn):
            ps_arns.extend(page.get("PermissionSets", []))
        emit(f"Found {len(ps_arns)} permission set(s)")

    # ── Describe permission sets (parallel) ─────────────────────────────────
    permission_sets = []
    total_ps = len(ps_arns)
    _describe_lock = Lock()
    _describe_done = [0]

    def describe_one_ps(ps_arn: str) -> dict:
        try:
            desc_resp = sso_admin.describe_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=ps_arn
            )
            ps = desc_resp["PermissionSet"]
        except Exception:
            ps = {"Name": ps_arn.rsplit("/", 1)[-1], "PermissionSetArn": ps_arn}

        inline_policy = None
        try:
            inline_resp = sso_admin.get_inline_policy_for_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=ps_arn
            )
            if inline_resp.get("InlinePolicy"):
                inline_policy = json.loads(inline_resp["InlinePolicy"])
        except Exception as exc:
            _slog.record(exc, context="get_inline_policy_for_permission_set", resource=ps_arn)

        aws_managed = []
        try:
            mp_pag = sso_admin.get_paginator("list_managed_policies_in_permission_set")
            for page in mp_pag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                for p in page.get("AttachedManagedPolicies", []):
                    aws_managed.append({"name": p.get("Name", ""), "arn": p.get("Arn", "")})
        except Exception as exc:
            _slog.record(exc, context="list_managed_policies_in_permission_set", resource=ps_arn)

        cmp_refs = []
        try:
            cmp_pag = sso_admin.get_paginator("list_customer_managed_policy_references_in_permission_set")
            for page in cmp_pag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                for ref in page.get("CustomerManagedPolicyReferences", []):
                    cmp_refs.append({"name": ref.get("Name", ""), "path": ref.get("Path", "/")})
        except Exception as exc:
            _slog.record(exc, context="list_customer_managed_policy_references_in_permission_set", resource=ps_arn)

        # Permission boundary
        permission_boundary = None
        try:
            pb_resp = sso_admin.get_permissions_boundary_for_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=ps_arn
            )
            if pb_resp.get("PermissionsBoundary"):
                permission_boundary = pb_resp["PermissionsBoundary"]
        except Exception:
            pass  # ResourceNotFoundException is normal (no boundary set)

        with _describe_lock:
            _describe_done[0] += 1
            if _describe_done[0] % 5 == 0 or _describe_done[0] == total_ps:
                emit(f"Describing permission sets ({_describe_done[0]}/{total_ps})",
                     completed_units=_describe_done[0], total_units=total_ps, phase="describe")

        return {
            "arn": ps_arn,
            "name": ps.get("Name", ps_arn.rsplit("/", 1)[-1]),
            "description": ps.get("Description", ""),
            "session_duration": ps.get("SessionDuration", "PT1H"),
            "inline_policy": inline_policy,
            "aws_managed_policies": aws_managed,
            "customer_managed_policy_references": cmp_refs,
            "permission_boundary": permission_boundary,
        }

    workers = int(params.get("workers", MAX_WORKERS))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(describe_one_ps, arn) for arn in ps_arns]
        for fut in as_completed(futures):
            try:
                permission_sets.append(fut.result())
            except Exception as exc:
                _slog.record(exc, context="describe_one_ps_future")

    emit(f"Described {len(permission_sets)} permission set(s)", phase="assignments")

    # ── List assignments (parallel per permission set) ──────────────────────
    assignments = []
    _assign_lock = Lock()
    _assign_done = [0]
    name_cache: dict = {}
    _name_lock = Lock()
    target_accounts_set = set(target_accounts) if target_accounts else set()

    def resolve_name(principal_type: str, principal_id: str) -> str:
        key = (principal_type, principal_id)
        with _name_lock:
            if key in name_cache:
                return name_cache[key]
        try:
            if principal_type == "USER":
                resp = identity_store.describe_user(IdentityStoreId=identity_store_id, UserId=principal_id)
                name = resp.get("UserName") or resp.get("DisplayName") or principal_id
            else:
                resp = identity_store.describe_group(IdentityStoreId=identity_store_id, GroupId=principal_id)
                name = resp.get("DisplayName") or resp.get("GroupName") or principal_id
        except Exception as exc:
            _slog.record(exc, context=f"resolve_name({principal_type})", resource=principal_id)
            name = principal_id
        with _name_lock:
            name_cache[key] = name
        return name

    # Build ps_name lookup for fast reference
    ps_name_map = {ps["arn"]: ps["name"] for ps in permission_sets}

    def fetch_assignments_for_ps(ps_arn: str) -> list:
        results = []
        # Always ask IdC which accounts this PS is provisioned to, then
        # intersect with the user's target scope (if specified). This avoids
        # querying accounts where the PS doesn't exist AND accounts the user
        # doesn't care about.
        provisioned_accounts = []
        try:
            apag = sso_admin.get_paginator("list_accounts_for_provisioned_permission_set")
            for page in apag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                provisioned_accounts.extend(page.get("AccountIds", []))
        except Exception as exc:
            _slog.record(exc, context="list_accounts_for_provisioned_permission_set", resource=ps_arn)

        if target_accounts is not None:
            # Only query accounts that are both provisioned AND in the user's scope
            accounts_for_ps = [a for a in provisioned_accounts if a in target_accounts_set]
        else:
            accounts_for_ps = provisioned_accounts

        for acct in accounts_for_ps:
            try:
                asg_pag = sso_admin.get_paginator("list_account_assignments")
                for page in asg_pag.paginate(
                    InstanceArn=instance_arn, AccountId=acct, PermissionSetArn=ps_arn,
                ):
                    for a in page.get("AccountAssignments", []):
                        principal_type = a["PrincipalType"]
                        principal_id = a["PrincipalId"]
                        results.append({
                            "permission_set_arn": ps_arn,
                            "permission_set_name": ps_name_map.get(ps_arn, ""),
                            "account_id": acct,
                            "principal_type": principal_type,
                            "principal_id": principal_id,
                            "principal_display_name": resolve_name(principal_type, principal_id),
                        })
            except Exception as exc:
                _slog.record(exc, context="list_account_assignments", resource=f"{ps_arn}::{acct}")

        with _assign_lock:
            _assign_done[0] += 1
            if _assign_done[0] % 5 == 0 or _assign_done[0] == total_ps:
                emit(f"Fetching assignments ({_assign_done[0]}/{total_ps})",
                     completed_units=_assign_done[0], total_units=total_ps, phase="assignments")
        return results

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(fetch_assignments_for_ps, arn) for arn in ps_arns]
        for fut in as_completed(futures):
            try:
                assignments.extend(fut.result())
            except Exception as exc:
                _slog.record(exc, context="fetch_assignments_for_ps_future")

    emit(f"Inventory complete: {len(permission_sets)} permission sets, {len(assignments)} assignments",
         completed_units=total_ps, total_units=total_ps, phase="done")

    payload = {
        "instance_arn": instance_arn,
        "identity_store_id": identity_store_id,
        "hub_account_id": account_id,
        "account_scope": account_scope,
        "target_accounts": target_accounts,
        "permission_sets": permission_sets,
        "assignments": assignments,
        "total_permission_sets": len(permission_sets),
        "total_assignments": len(assignments),
        "suppressed_warnings": _slog.get_summary(),
    }
    return cache.write_cache(config.IDC_CACHE, payload)


# ─── Generate IaC ────────────────────────────────────────────────────────────

def _iso8601_to_seconds(duration: str) -> int:
    """Convert an ISO 8601 duration like PT1H, PT4H30M, PT12H to seconds."""
    import re as _re
    m = _re.match(r"PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?", duration, _re.IGNORECASE)
    if not m:
        return 0
    hours = int(m.group(1) or 0)
    minutes = int(m.group(2) or 0)
    seconds = int(m.group(3) or 0)
    return hours * 3600 + minutes * 60 + seconds


def generate_iac(params: dict) -> dict:
    """
    Generate CloudFormation templates from cached inventory or provided role mappings.
    """
    import re
    import yaml as _yaml

    cached = cache.read_cache(config.IDC_CACHE)
    if cached and cached.get("data"):
        data = cached["data"]
        permission_sets = data.get("permission_sets", [])
        assignments = data.get("assignments", [])
    else:
        # No cache — build from role_mappings in the request payload
        role_mappings_input = params.get("role_mappings") or []
        if not role_mappings_input:
            raise ValueError("No inventory cached and no role_mappings provided. Run discovery first or upload a migration plan.")
        permission_sets = []
        seen_ps: set = set()
        for rm in role_mappings_input:
            ps_name = rm.get("psName", "")
            if ps_name and ps_name not in seen_ps:
                seen_ps.add(ps_name)
                permission_sets.append({
                    "arn": rm.get("psArn", f"unknown/{ps_name}"),
                    "name": ps_name,
                    "description": "",
                    "session_duration": "PT1H",
                    "inline_policy": None,
                    "aws_managed_policies": [],
                    "customer_managed_policy_references": [],
                    "permission_boundary": None,
                })
        assignments = [{"permission_set_arn": rm.get("psArn", ""), "account_id": rm.get("accountId", ""),
                        "principal_type": "GROUP", "principal_id": rm.get("principal", ""),
                        "principal_display_name": rm.get("principal", ""),
                        "permission_set_name": rm.get("psName", "")} for rm in role_mappings_input if rm.get("principal")]

    if not permission_sets:
        raise ValueError("No permission sets in cached inventory.")

    role_path = params.get("role_path") or "/aam/"
    role_name_template = params.get("role_name_template") or "AAM-{name}"
    aam_application_arn = params.get("aam_application_arn")
    aam_source_account = params.get("aam_source_account") or ""
    include_tag_session = params.get("include_tag_session", True)

    # Filter to selected permission sets if specified
    selected_ps_arns = params.get("selected_permission_sets")
    if selected_ps_arns:
        permission_sets = [ps for ps in permission_sets if ps["arn"] in selected_ps_arns]
        assignments = [a for a in assignments if a["permission_set_arn"] in selected_ps_arns]

    def sanitize(name: str) -> str:
        return re.sub(r"[^a-zA-Z0-9]", "", name)

    # Group assignments by account
    from collections import defaultdict
    assignments_by_account: dict[str, list] = defaultdict(list)
    for a in assignments:
        assignments_by_account[a["account_id"]].append(a)

    # If all assignments are in one account, produce a single template.
    # Otherwise produce per-account templates.
    accounts = sorted(assignments_by_account.keys())
    if not accounts:
        accounts = [data.get("hub_account_id", "unknown")]

    role_map: dict = {}  # ps_arn -> role_name
    # Use explicit role mappings from the frontend if provided (user-edited names),
    # otherwise fall back to the template pattern.
    role_mappings_input = params.get("role_mappings") or []
    role_map_from_user = {}
    for rm in role_mappings_input:
        ps_arn = rm.get("psArn", "")
        rn = rm.get("roleName", "")
        if ps_arn and rn:
            role_map_from_user[ps_arn] = rn
        elif rm.get("psName") and rn:
            # Match by name if ARN not available
            for ps in permission_sets:
                if ps["name"] == rm["psName"]:
                    role_map_from_user[ps["arn"]] = rn

    for ps in permission_sets:
        if ps["arn"] in role_map_from_user:
            role_map[ps["arn"]] = role_map_from_user[ps["arn"]]
        else:
            role_map[ps["arn"]] = role_name_template.replace("{name}", ps["name"])

    def build_template_for_account(account_id: str, account_assignments: list) -> str:
        """Build a CloudFormation YAML string for one account's roles (no entitlements)."""
        import yaml as _yaml

        ps_arns_for_account = {a["permission_set_arn"] for a in account_assignments}
        account_ps = [ps for ps in permission_sets if ps["arn"] in ps_arns_for_account]

        # Trust statement with conditions
        _actions = ["sts:AssumeRole", "sts:SetContext", "sts:TagSession"]
        if not include_tag_session:
            _actions = [a for a in _actions if a != "sts:TagSession"]
        trust_stmt: dict = {
            "Sid": "AAMTrustPolicyStatement",
            "Effect": "Allow",
            "Principal": {"Service": "account-access.amazonaws.com"},
            "Action": _actions,
        }
        if aam_source_account or aam_application_arn:
            cond: dict = {"StringEquals": {}}
            if aam_source_account:
                cond["StringEquals"]["aws:SourceAccount"] = aam_source_account
            if aam_application_arn:
                cond["StringEquals"]["aws:SourceArn"] = aam_application_arn
            trust_stmt["Condition"] = cond

        resources: dict = {}

        for ps in account_ps:
            role_name = role_map.get(ps["arn"], "")
            if not role_name:
                continue
            logical_id = sanitize(ps["name"]) + "Role"

            role_props: dict = {
                "RoleName": role_name,
                "Path": role_path,
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [trust_stmt]},
                "Tags": [
                    {"Key": "ManagedBy", "Value": "AAM-Migration"},
                    {"Key": "SourcePermissionSet", "Value": ps["name"]},
                ],
            }

            # MaxSessionDuration from the permission set's session duration (ISO 8601 → seconds)
            session_dur = ps.get("session_duration", "")
            if session_dur:
                secs = _iso8601_to_seconds(session_dur)
                if secs and secs != 3600:  # 3600 is the IAM default, skip if unchanged
                    role_props["MaxSessionDuration"] = secs

            # Managed policies
            managed_arns = [p["arn"] for p in ps.get("aws_managed_policies", [])]
            for ref in ps.get("customer_managed_policy_references", []):
                path = ref.get("path", "/")
                managed_arns.append({"Fn::Sub": f"arn:aws:iam::${{AWS::AccountId}}:policy{path}{ref['name']}"})
            if managed_arns:
                role_props["ManagedPolicyArns"] = managed_arns

            # Inline policy
            if ps.get("inline_policy"):
                role_props["Policies"] = [{
                    "PolicyName": f"{role_name}-inline",
                    "PolicyDocument": ps["inline_policy"],
                }]

            # Permission boundary
            if ps.get("permission_boundary"):
                pb = ps["permission_boundary"]
                if pb.get("ManagedPolicyArn"):
                    role_props["PermissionsBoundary"] = pb["ManagedPolicyArn"]
                elif pb.get("CustomerManagedPolicyReference"):
                    ref = pb["CustomerManagedPolicyReference"]
                    pb_path = ref.get("Path", "/")
                    pb_name = ref.get("Name", "")
                    role_props["PermissionsBoundary"] = {"Fn::Sub": f"arn:aws:iam::${{AWS::AccountId}}:policy{pb_path}{pb_name}"}

            resources[logical_id] = {"Type": "AWS::IAM::Role", "Properties": role_props}

        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"IAM roles for account {account_id} migrated from IdC to AAM. Generated by AAM Migration Tool.",
            "Resources": resources,
        }

        return _yaml.safe_dump(template, sort_keys=False, default_flow_style=False)

    def build_entitlements_template(all_assignments: list) -> str:
        """Build a separate CloudFormation template for AAM entitlements (deployed in the management account)."""
        import yaml as _yaml

        resources: dict = {}
        seen_ent: set = set()

        for i, a in enumerate(all_assignments):
            ps_arn = a["permission_set_arn"]
            rn = role_map.get(ps_arn, "")
            if not rn:
                continue
            account_id = a.get("account_id", "")
            logical = sanitize(f"{a['principal_display_name']}{account_id}{i}")[:50] + "Ent"
            while logical in seen_ent:
                logical += "x"
            seen_ent.add(logical)
            id_key = "UserId" if a["principal_type"] == "USER" else "GroupId"
            # Construct the full role ARN since the role lives in a different account/template
            role_arn = f"arn:aws:iam::{account_id}:role{role_path}{rn}"
            resources[logical] = {
                "Type": "AWS::AccountAccess::Entitlement",
                "Properties": {
                    "ApplicationArn": aam_application_arn,
                    "Entitlement": {
                        "PrincipalRole": {
                            "Principal": {"IdentityCenter": {id_key: a["principal_id"]}},
                            "RoleArn": role_arn,
                        },
                    },
                },
            }

        if not resources:
            return ""

        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "AAM entitlements for IdC migration. Deploy in the AAM management account. Generated by AAM Migration Tool.",
            "Resources": resources,
        }

        return _yaml.safe_dump(template, sort_keys=False, default_flow_style=False)

    # Generate templates
    os.makedirs(config.CACHE_DIR, exist_ok=True)
    templates: dict[str, dict] = {}  # account_id -> {path, content}

    for account_id in accounts:
        account_assignments = assignments_by_account.get(account_id, [])
        content = build_template_for_account(account_id, account_assignments)
        if len(accounts) == 1:
            filename = "idc_roles_cloudformation.yaml"
        else:
            filename = f"idc_roles_{account_id}.yaml"
        cfn_path = os.path.join(config.CACHE_DIR, filename)
        with open(cfn_path, "w", encoding="utf-8") as f:
            f.write(content)
        templates[account_id] = {"path": cfn_path, "content": content}

    # Generate a separate entitlements template for the AAM management account
    entitlements_template: dict | None = None
    if aam_application_arn and assignments:
        ent_content = build_entitlements_template(assignments)
        if ent_content:
            ent_filename = "idc_entitlements_cloudformation.yaml"
            ent_path = os.path.join(config.CACHE_DIR, ent_filename)
            with open(ent_path, "w", encoding="utf-8") as f:
                f.write(ent_content)
            entitlements_template = {"path": ent_path, "content": ent_content}

    return {
        "roles_count": len(permission_sets),
        "entitlements_count": len(assignments) if aam_application_arn else 0,
        "templates": templates,
        "entitlements_template": entitlements_template,
        "accounts": accounts,
        "role_map": role_map,
    }


# ─── Apply directly (create roles + entitlements via API) ────────────────────

def apply_roles(params: dict, on_progress: Optional[ProgressCb] = None) -> dict:
    """
    Create IAM roles and optionally AAM entitlements directly via API.

    This is the "apply" mode — it mutates the target account(s). Each role
    is created with the AAM trust policy and the policies from the permission
    set. Results are returned per-role with success/failure status.

    Args:
        params: dict with auth fields + role_path, role_name_template,
                aam_application_arn (optional), selected_permission_sets (optional).
        on_progress: optional progress callback.

    Returns:
        dict with per-role results and summary.
    """
    cached = cache.read_cache(config.IDC_CACHE)
    if cached and cached.get("data"):
        data = cached["data"]
        permission_sets = data.get("permission_sets", [])
        assignments = data.get("assignments", [])
    else:
        # No cache — build from role_mappings in the request payload
        role_mappings_input = params.get("role_mappings") or []
        if not role_mappings_input:
            raise ValueError("No inventory cached and no role_mappings provided. Run discovery first or upload a migration plan.")
        permission_sets = []
        seen_ps: set = set()
        for rm in role_mappings_input:
            ps_name = rm.get("psName", "")
            if ps_name and ps_name not in seen_ps:
                seen_ps.add(ps_name)
                permission_sets.append({
                    "arn": rm.get("psArn", f"unknown/{ps_name}"),
                    "name": ps_name,
                    "description": "",
                    "session_duration": "PT1H",
                    "inline_policy": None,
                    "aws_managed_policies": [],
                    "customer_managed_policy_references": [],
                    "permission_boundary": None,
                })
        assignments = [{"permission_set_arn": rm.get("psArn", ""), "account_id": rm.get("accountId", ""),
                        "principal_type": "GROUP", "principal_id": rm.get("principal", ""),
                        "principal_display_name": rm.get("principal", ""),
                        "permission_set_name": rm.get("psName", "")} for rm in role_mappings_input if rm.get("principal")]

    role_path = params.get("role_path") or "/aam/"
    role_name_template = params.get("role_name_template") or "AAM-{name}"
    aam_application_arn = params.get("aam_application_arn")

    # Filter to selected permission sets
    selected_ps_arns = params.get("selected_permission_sets")
    if selected_ps_arns:
        permission_sets = [ps for ps in permission_sets if ps["arn"] in selected_ps_arns]
        assignments = [a for a in assignments if a["permission_set_arn"] in selected_ps_arns]

    # Filter to selected assignments if provided
    selected_assignments_list = params.get("selected_assignments")
    if selected_assignments_list:
        selected_keys = {
            (sa["permission_set_arn"], sa["account_id"], sa["principal_id"])
            for sa in selected_assignments_list
        }
        assignments = [
            a for a in assignments
            if (a["permission_set_arn"], a["account_id"], a["principal_id"]) in selected_keys
        ]

    # Resolve sessions for the target accounts
    session = _resolve_hub_session(params)

    # For multi-account, we need per-account sessions.
    # IMPORTANT: only resolve sessions for accounts that are actually in scope
    # (derived from the filtered assignments), not all accounts in the inventory.
    auth_method = params.get("auth_method") or "profiles"
    account_sessions: dict = {}

    # Collect unique target accounts from the FILTERED assignments only
    target_account_ids = sorted({a["account_id"] for a in assignments})

    if auth_method == "assume_role":
        role_name_assume = (params.get("role_name") or "").strip()
        base_session = build_session(None)
        base_account = base_session.client("sts").get_caller_identity()["Account"]
        for acct in target_account_ids:
            if acct == base_account:
                account_sessions[acct] = base_session
            elif role_name_assume:
                try:
                    account_sessions[acct] = build_assumed_session(acct, role_name_assume)
                except Exception:
                    account_sessions[acct] = None
            else:
                account_sessions[acct] = session
    else:
        # Profiles mode: resolve each profile to its account via GetCallerIdentity,
        # then map account_id -> session. For single-account (no profiles), the hub
        # session is used for all targets.
        profiles = params.get("profiles") or []
        if profiles:
            for profile in profiles:
                try:
                    prof_session = build_session(profile)
                    prof_account = prof_session.client("sts").get_caller_identity()["Account"]
                    account_sessions[prof_account] = prof_session
                except Exception as exc:
                    _slog.record(exc, context="resolve_profile_session", resource=profile)
        # For any target accounts not covered by a profile, fall back to the hub session
        for acct in target_account_ids:
            if acct not in account_sessions:
                account_sessions[acct] = session

    # Build role_name map
    role_map: dict = {}
    for ps in permission_sets:
        role_map[ps["arn"]] = role_name_template.replace("{name}", ps["name"])

    # Determine unique (permission_set, account) pairs to create roles for
    pairs = sorted({(a["permission_set_arn"], a["account_id"]) for a in assignments})
    total = len(pairs)
    completed = 0
    results: list[dict] = []
    workers = int(params.get("workers", MAX_WORKERS))

    # Build the trust policy with confused-deputy conditions
    aam_source_account = params.get("aam_source_account") or ""
    aam_app_arn = params.get("aam_application_arn") or ""
    _actions = ["sts:AssumeRole", "sts:SetContext", "sts:TagSession"]
    if not params.get("include_tag_session", True):
        _actions = [a for a in _actions if a != "sts:TagSession"]
    trust_stmt: dict = {
        "Sid": "AAMTrustPolicyStatement",
        "Effect": "Allow",
        "Principal": {"Service": "account-access.amazonaws.com"},
        "Action": _actions,
    }
    if aam_source_account or aam_app_arn:
        trust_stmt["Condition"] = {"StringEquals": {}}
        if aam_source_account:
            trust_stmt["Condition"]["StringEquals"]["aws:SourceAccount"] = aam_source_account
        if aam_app_arn:
            trust_stmt["Condition"]["StringEquals"]["aws:SourceArn"] = aam_app_arn
    trust_policy = json.dumps({"Version": "2012-10-17", "Statement": [trust_stmt]})

    def emit(msg: str):
        if on_progress:
            on_progress({
                "completed_units": completed,
                "total_units": total,
                "skipped_units": 0,
                "message": msg,
            })

    emit(f"Creating {total} role(s) across {len(target_account_ids)} account(s)")

    ps_by_arn = {ps["arn"]: ps for ps in permission_sets}
    _apply_lock = Lock()

    def create_one_role(pair: tuple) -> dict:
        nonlocal completed
        ps_arn, acct_id = pair
        role_name = role_map.get(ps_arn, "")
        ps = ps_by_arn.get(ps_arn)
        acct_session = account_sessions.get(acct_id)
        warnings: list[str] = []

        if not role_name or not ps:
            return {
                "role_name": role_name or "(unknown)",
                "role_arn": "",
                "account_id": acct_id,
                "permission_set": ps["name"] if ps else ps_arn,
                "status": "error",
                "error": "missing role name or permission set data",
                "timestamp": _now(),
            }

        if not acct_session:
            return {
                "role_name": role_name,
                "role_arn": "",
                "account_id": acct_id,
                "permission_set": ps["name"],
                "status": "error",
                "error": f"No session available for account {acct_id}",
                "timestamp": _now(),
            }

        iam = acct_session.client("iam")
        target_arn = f"arn:aws:iam::{acct_id}:role{role_path}{role_name}"

        try:
            # Idempotency check
            try:
                iam.get_role(RoleName=role_name)
                return {
                    "role_name": role_name,
                    "role_arn": target_arn,
                    "account_id": acct_id,
                    "permission_set": ps["name"],
                    "status": "already exists",
                    "timestamp": _now(),
                }
            except Exception as e:
                if "NoSuchEntity" not in str(e):
                    raise

            # Create the role
            create_kwargs = dict(
                RoleName=role_name,
                Path=role_path,
                AssumeRolePolicyDocument=trust_policy,
                Description=f"Created by AAM Migration Tool for permission set {ps['name']}",
                Tags=[{"Key": "ManagedBy", "Value": "AAM-Migration"},
                      {"Key": "SourcePermissionSet", "Value": ps["name"]}],
            )
            session_dur = ps.get("session_duration", "")
            if session_dur:
                secs = _iso8601_to_seconds(session_dur)
                if secs and secs != 3600:
                    create_kwargs["MaxSessionDuration"] = secs
            iam.create_role(**create_kwargs)

            # Attach AWS managed policies
            for p in ps.get("aws_managed_policies", []):
                try:
                    iam.attach_role_policy(RoleName=role_name, PolicyArn=p["arn"])
                except Exception as exc:
                    warnings.append(f"Failed to attach managed policy {p['arn']}: {exc}")

            # Attach CMP references
            for ref in ps.get("customer_managed_policy_references", []):
                path = ref.get("path", "/")
                cmp_arn = f"arn:aws:iam::{acct_id}:policy{path}{ref['name']}"
                try:
                    iam.attach_role_policy(RoleName=role_name, PolicyArn=cmp_arn)
                except Exception as exc:
                    warnings.append(f"Failed to attach CMP {cmp_arn}: {exc}")

            # Inline policy
            if ps.get("inline_policy"):
                try:
                    iam.put_role_policy(
                        RoleName=role_name,
                        PolicyName=f"{role_name}-inline",
                        PolicyDocument=json.dumps(ps["inline_policy"]),
                    )
                except Exception as exc:
                    warnings.append(f"Failed to attach inline policy: {exc}")

            result = {
                "role_name": role_name,
                "role_arn": target_arn,
                "account_id": acct_id,
                "permission_set": ps["name"],
                "status": "created",
                "timestamp": _now(),
            }
            if warnings:
                result["warnings"] = warnings
                result["error"] = f"{len(warnings)} policy attach failure(s)"
            return result

        except Exception as exc:
            return {
                "role_name": role_name,
                "role_arn": "",
                "account_id": acct_id,
                "permission_set": ps["name"],
                "status": "error",
                "error": str(exc),
                "timestamp": _now(),
            }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(create_one_role, pair): pair for pair in pairs}
        for fut in as_completed(futures):
            result = fut.result()
            results.append(result)
            with _apply_lock:
                completed += 1
                emit(f"{result['status'].title()}: {result['role_name']}")

    summary = {
        "total": total,
        "created": len([r for r in results if r["status"] == "created"]),
        "existing": len([r for r in results if r["status"] == "existing"]),
        "error": len([r for r in results if r["status"] == "error"]),
    }

    # ── Phase 2: Create AAM entitlements ─────────────────────────────────────
    # Entitlements map each assignment (principal → role in account) to the AAM
    # application. They are created in the hub account (where AAM lives), not
    # in the spoke accounts.
    #
    # IAM is eventually consistent — a newly created role may not be resolvable
    # by AAM immediately. Individual entitlement calls retry on ValidationException.
    import time

    entitlement_results: list[dict] = []

    if aam_application_arn:
        # Build a lookup of successful role ARNs: (ps_arn, account_id) -> role_arn
        role_arn_lookup: dict[tuple[str, str], str] = {}
        for r in results:
            if r["status"] in ("created", "already exists") and r["role_arn"]:
                # Find the ps_arn from the role_map
                for ps_arn_key, rn in role_map.items():
                    if rn == r["role_name"] and r["account_id"]:
                        role_arn_lookup[(ps_arn_key, r["account_id"])] = r["role_arn"]
                        break

        # Filter assignments to only those we have roles for
        eligible_assignments = [
            a for a in assignments
            if (a["permission_set_arn"], a["account_id"]) in role_arn_lookup
        ]

        # Also filter by selected_assignments if provided
        selected_assignments_list = params.get("selected_assignments")
        if selected_assignments_list:
            selected_keys = {
                (sa["permission_set_arn"], sa["account_id"], sa["principal_id"])
                for sa in selected_assignments_list
            }
            eligible_assignments = [
                a for a in eligible_assignments
                if (a["permission_set_arn"], a["account_id"], a["principal_id"]) in selected_keys
            ]

        total_ent = len(eligible_assignments)
        ent_completed = 0

        if total_ent > 0:
            emit(f"Creating {total_ent} AAM entitlement(s)")

            # Use the hub session for AAM (entitlements live in the management account)
            try:
                aam_region = params.get("aam_region") or params.get("region") or "us-east-1"
                # IMPORTANT: AAM entitlements live in the hub/management account,
                # not the target accounts. Use default creds (same as IdC discovery).
                hub_session_for_aam = build_session(None)
                aam_client = hub_session_for_aam.client("account-access", region_name=aam_region)
            except Exception as exc:
                # If the AAM client can't be created (missing custom SDK), report all as failed
                for a in eligible_assignments:
                    entitlement_results.append({
                        "principal": a["principal_display_name"],
                        "principal_type": a["principal_type"],
                        "principal_id": a["principal_id"],
                        "account_id": a["account_id"],
                        "role_arn": role_arn_lookup.get((a["permission_set_arn"], a["account_id"]), ""),
                        "status": "error",
                        "error": f"AAM client unavailable: {exc}",
                        "timestamp": _now(),
                    })
                aam_client = None

            if aam_client:
                for a in eligible_assignments:
                    role_arn = role_arn_lookup.get((a["permission_set_arn"], a["account_id"]), "")
                    principal_type = a["principal_type"]
                    principal_id = a["principal_id"]

                    # Build the principal block for AAM
                    principal_block: dict = {}
                    if principal_type == "USER":
                        principal_block["userId"] = principal_id
                    else:
                        principal_block["groupId"] = principal_id

                    try:
                        # Retry up to 3 times for ValidationException (IAM propagation delay)
                        max_retries = 3
                        last_exc = None
                        for attempt in range(max_retries):
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
                                last_exc = None
                                break
                            except Exception as retry_exc:
                                if "ValidationException" in str(retry_exc) and attempt < max_retries - 1:
                                    last_exc = retry_exc
                                    time.sleep(3 * (attempt + 1))  # 3s, 6s backoff
                                else:
                                    raise retry_exc

                        if last_exc is None:
                            entitlement_results.append({
                                "principal": a["principal_display_name"],
                                "principal_type": principal_type,
                                "principal_id": principal_id,
                                "account_id": a["account_id"],
                                "role_arn": role_arn,
                                "entitlement_id": resp.get("entitlementId", ""),
                                "status": "created",
                                "timestamp": _now(),
                            })
                    except Exception as exc:
                        error_str = str(exc)
                        # Handle conflict (entitlement already exists)
                        status = "existing" if "Conflict" in error_str or "AlreadyExists" in error_str else "error"
                        entitlement_results.append({
                            "principal": a["principal_display_name"],
                            "principal_type": principal_type,
                            "principal_id": principal_id,
                            "account_id": a["account_id"],
                            "role_arn": role_arn,
                            "entitlement_id": "",
                            "status": status,
                            "error": error_str if status == "error" else "already exists",
                            "timestamp": _now(),
                        })

                    ent_completed += 1
                    if on_progress:
                        on_progress({
                            "completed_units": total + ent_completed,
                            "total_units": total + total_ent,
                            "skipped_units": 0,
                            "message": f"Entitlement {ent_completed}/{total_ent}: {a['principal_display_name']}",
                        })

    summary["entitlements_created"] = len([e for e in entitlement_results if e["status"] == "created"])
    summary["entitlements_existing"] = len([e for e in entitlement_results if e["status"] == "existing"])
    summary["entitlements_error"] = len([e for e in entitlement_results if e["status"] == "error"])
    summary["entitlements_total"] = len(entitlement_results)

    # Debug info for troubleshooting entitlement creation
    debug = {
        "aam_application_arn_provided": bool(aam_application_arn),
        "role_arn_lookup_count": len(role_arn_lookup) if aam_application_arn else 0,
        "eligible_assignments_count": len(eligible_assignments) if aam_application_arn else 0,
        "total_assignments_in_inventory": len(assignments),
        "role_results_statuses": {s: len([r for r in results if r["status"] == s]) for s in set(r["status"] for r in results)},
    }

    return {
        "results": results,
        "entitlement_results": entitlement_results,
        "summary": summary,
        "debug": debug,
    }


# ─── Read cached state ───────────────────────────────────────────────────────

def get_state() -> Optional[dict]:
    """Return cached inventory (permission sets + assignments), or None."""
    return cache.read_cache(config.IDC_CACHE)


# ─── Targeted discovery (resolve migration plan) ─────────────────────────────

def resolve_plan(params: dict) -> dict:
    """
    Targeted discovery from a migration plan upload.

    For each permission set referenced in the plan:
      - DescribePermissionSet + fetch policies (managed, inline, CMP, boundary)
    For each principal name:
      - Resolve to Identity Store UUID via GetGroupId/GetUserId

    Populates the cache and returns enriched data ready for the UI.

    params:
      - role_mappings: list of {psName, psArn (optional), roleName, principal, accountId, principal_type}
      - region: IdC region
      - auth fields (for session resolution)
    """
    from botocore.config import Config as BotoConfig

    role_mappings_input = params.get("role_mappings") or []
    if not role_mappings_input:
        raise ValueError("role_mappings is required")

    region = params.get("region") or "us-east-1"
    session = _resolve_hub_session(params)

    boto_cfg = BotoConfig(retries={"mode": "adaptive", "max_attempts": 5}, max_pool_connections=10)
    sso_admin = session.client("sso-admin", region_name=region, config=boto_cfg)
    identity_store = session.client("identitystore", region_name=region, config=boto_cfg)

    # Discover IdC instance
    instances = []
    for page in sso_admin.get_paginator("list_instances").paginate():
        instances.extend(page.get("Instances", []))
    if not instances:
        raise RuntimeError("No IAM Identity Center instance found")

    instance_arn = instances[0]["InstanceArn"]
    identity_store_id = instances[0]["IdentityStoreId"]

    # Collect unique permission set references from the plan
    ps_names = {rm.get("psName", "") for rm in role_mappings_input if rm.get("psName")}
    ps_arns_input = {rm.get("psArn", "") for rm in role_mappings_input if rm.get("psArn") and rm["psArn"].startswith("arn:")}

    # If we have ARNs, use them directly. Otherwise look up by name.
    ps_arns_to_describe: list[str] = list(ps_arns_input)

    if ps_names and not ps_arns_to_describe:
        # Need to list all PS to find ARNs by name
        all_ps_arns = []
        for page in sso_admin.get_paginator("list_permission_sets").paginate(InstanceArn=instance_arn):
            all_ps_arns.extend(page.get("PermissionSets", []))
        # Describe each to match by name
        for arn in all_ps_arns:
            try:
                resp = sso_admin.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=arn)
                name = resp["PermissionSet"].get("Name", "")
                if name in ps_names:
                    ps_arns_to_describe.append(arn)
            except Exception:
                pass

    # Fetch policies for each permission set. Also call DescribePermissionSet to
    # get the description and session duration (needed for the UI table and for
    # setting MaxSessionDuration on the created role).
    _idc_lib = _load_idc_lib()
    permission_sets = []
    ps_errors = []
    for ps_arn in ps_arns_to_describe:
        # Find the name from the role_mappings input
        ps_name = ""
        for rm in role_mappings_input:
            if rm.get("psArn") == ps_arn:
                ps_name = rm.get("psName", "")
                break
        try:
            ps_data = _idc_lib.fetch_permission_set_policies(sso_admin, instance_arn, ps_arn, ps_name)
        except Exception as exc:
            _slog.record(exc, context="resolve_plan_fetch_policies", resource=ps_arn)
            ps_errors.append({"psArn": ps_arn, "psName": ps_name, "error": f"Policy fetch failed: {exc}"})
            continue
        # Enrich with description + session_duration from DescribePermissionSet
        try:
            desc_resp = sso_admin.describe_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=ps_arn
            )
            ps_meta = desc_resp.get("PermissionSet", {})
            ps_data["description"] = ps_meta.get("Description", "")
            ps_data["session_duration"] = ps_meta.get("SessionDuration", "PT1H")
            if not ps_data["name"] or ps_data["name"] == ps_arn.rsplit("/", 1)[-1]:
                ps_data["name"] = ps_meta.get("Name", ps_data["name"])
        except Exception as exc:
            _slog.record(exc, context="resolve_plan_describe_ps", resource=ps_arn)
            ps_errors.append({"psArn": ps_arn, "psName": ps_name, "error": f"DescribePermissionSet failed: {exc}"})
        permission_sets.append(ps_data)

    # Build a name→ARN lookup
    ps_name_to_arn = {ps["name"]: ps["arn"] for ps in permission_sets}

    # Resolve principal names to UUIDs
    resolved_mappings = []
    for rm in role_mappings_input:
        principal_name = rm.get("principal", "")
        principal_type = rm.get("principal_type") or rm.get("principalType") or "GROUP"
        ps_name = rm.get("psName", "")
        ps_arn = rm.get("psArn", "") or ps_name_to_arn.get(ps_name, "")

        # Resolve principal to UUID (skip if already a UUID)
        principal_id = principal_name
        resolution_error = None
        if principal_name:
            import re as _re
            _UUID_RE = _re.compile(r"^([0-9a-f]{10}-)?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$")
            if _UUID_RE.match(principal_name):
                principal_id = principal_name
            else:
                try:
                    if principal_type.upper() == "USER":
                        resp = identity_store.get_user_id(
                            IdentityStoreId=identity_store_id,
                            AlternateIdentifier={"UniqueAttribute": {"AttributePath": "userName", "AttributeValue": principal_name}},
                        )
                        principal_id = resp["UserId"]
                    else:
                        resp = identity_store.get_group_id(
                            IdentityStoreId=identity_store_id,
                            AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": principal_name}},
                        )
                        principal_id = resp["GroupId"]
                except Exception as exc:
                    resolution_error = str(exc)
                    # Keep the display name as fallback

        resolved_mappings.append({
            "key": f"{ps_arn}#{rm.get('accountId', '')}#{principal_id}",
            "psArn": ps_arn,
            "psName": ps_name,
            "roleName": rm.get("roleName", f"AAM-{ps_name}"),
            "principal": principal_name,
            "principal_id": principal_id,
            "accountId": rm.get("accountId", ""),
            "principal_type": principal_type,
            "resolution_error": resolution_error,
        })

    # Build assignments from the resolved mappings (for cache + UI)
    assignments = []
    for rm in resolved_mappings:
        if rm["principal_id"] and rm["psArn"] and rm["accountId"]:
            assignments.append({
                "permission_set_arn": rm["psArn"],
                "permission_set_name": rm["psName"],
                "account_id": rm["accountId"],
                "principal_type": rm.get("principal_type", "GROUP"),
                "principal_id": rm["principal_id"],
                "principal_display_name": rm["principal"],
            })

    # Write to cache so generate_iac/apply_roles can use it
    account_id = session.client("sts").get_caller_identity()["Account"]
    payload = {
        "instance_arn": instance_arn,
        "identity_store_id": identity_store_id,
        "hub_account_id": account_id,
        "account_scope": "plan-upload",
        "permission_sets": permission_sets,
        "assignments": assignments,
        "total_permission_sets": len(permission_sets),
        "total_assignments": len(assignments),
    }
    cache.write_cache(config.IDC_CACHE, payload)

    return {
        "permission_sets": permission_sets,
        "assignments": assignments,
        "resolved_mappings": resolved_mappings,
        "errors": [rm for rm in resolved_mappings if rm.get("resolution_error")],
        "ps_errors": ps_errors,
    }
