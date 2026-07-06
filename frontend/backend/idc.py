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

# ─── Import the IdC tool modules by path ─────────────────────────────────────

_IDC_DIR = os.path.join(config.REPO_ROOT, "Identity Center to AAM")

ProgressCb = Callable[[dict], None]

# Default concurrency for parallel operations. Uses adaptive retry so throttle
# responses are handled gracefully.
MAX_WORKERS = 5


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
        except Exception:
            pass

        aws_managed = []
        try:
            mp_pag = sso_admin.get_paginator("list_managed_policies_in_permission_set")
            for page in mp_pag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                for p in page.get("AttachedManagedPolicies", []):
                    aws_managed.append({"name": p.get("Name", ""), "arn": p.get("Arn", "")})
        except Exception:
            pass

        cmp_refs = []
        try:
            cmp_pag = sso_admin.get_paginator("list_customer_managed_policy_references_in_permission_set")
            for page in cmp_pag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                for ref in page.get("CustomerManagedPolicyReferences", []):
                    cmp_refs.append({"name": ref.get("Name", ""), "path": ref.get("Path", "/")})
        except Exception:
            pass

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
        }

    workers = int(params.get("workers", MAX_WORKERS))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(describe_one_ps, arn) for arn in ps_arns]
        for fut in as_completed(futures):
            try:
                permission_sets.append(fut.result())
            except Exception:
                pass

    emit(f"Described {len(permission_sets)} permission set(s)", phase="assignments")

    # ── List assignments (parallel per permission set) ──────────────────────
    assignments = []
    _assign_lock = Lock()
    _assign_done = [0]
    name_cache: dict = {}
    _name_lock = Lock()

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
        except Exception:
            name = principal_id
        with _name_lock:
            name_cache[key] = name
        return name

    # Build ps_name lookup for fast reference
    ps_name_map = {ps["arn"]: ps["name"] for ps in permission_sets}

    def fetch_assignments_for_ps(ps_arn: str) -> list:
        results = []
        if target_accounts is not None:
            accounts_for_ps = target_accounts
        else:
            accounts_for_ps = []
            try:
                apag = sso_admin.get_paginator("list_accounts_for_provisioned_permission_set")
                for page in apag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                    accounts_for_ps.extend(page.get("AccountIds", []))
            except Exception:
                pass

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
            except Exception:
                pass

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
            except Exception:
                pass

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
    }
    return cache.write_cache(config.IDC_CACHE, payload)


# ─── Generate IaC ────────────────────────────────────────────────────────────

def generate_iac(params: dict) -> dict:
    """
    Generate CloudFormation templates from cached inventory.

    For multi-account scenarios (assignments span multiple accounts), produces
    one template per account. For single-account, produces a single template.
    Each template contains only the roles and entitlements for that account.
    """
    import re

    cached = cache.read_cache(config.IDC_CACHE)
    if not cached or not cached.get("data"):
        raise ValueError("No inventory cached. Run discovery first.")

    data = cached["data"]
    permission_sets = data.get("permission_sets", [])
    assignments = data.get("assignments", [])

    if not permission_sets:
        raise ValueError("No permission sets in cached inventory.")

    role_path = params.get("role_path") or "/aam/"
    role_name_template = params.get("role_name_template") or "AAM-{name}"
    aam_application_arn = params.get("aam_application_arn")

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
    for ps in permission_sets:
        role_name = role_name_template.replace("{name}", ps["name"])
        role_map[ps["arn"]] = role_name

    def build_template_for_account(account_id: str, account_assignments: list) -> str:
        """Build a CloudFormation YAML string for one account."""
        # Permission sets relevant to this account
        ps_arns_for_account = {a["permission_set_arn"] for a in account_assignments}
        account_ps = [ps for ps in permission_sets if ps["arn"] in ps_arns_for_account]

        lines = []
        lines.append("AWSTemplateFormatVersion: '2010-09-09'")
        lines.append("Description: >-")
        lines.append(f"  IAM roles for account {account_id} migrated from IdC permission sets to AAM.")
        lines.append("  Generated by Truffle IdC-to-AAM tool.")
        lines.append("")
        lines.append("Parameters:")
        lines.append("  TrustServicePrincipal:")
        lines.append("    Type: String")
        lines.append("    Default: account-access-preview.amazonaws.com")
        lines.append("    Description: The service principal for the new trust relationship.")
        lines.append("")
        lines.append("Resources:")

        for ps in account_ps:
            role_name = role_map.get(ps["arn"], "")
            if not role_name:
                continue
            logical_id = sanitize(ps["name"]) + "Role"

            lines.append("")
            lines.append(f"  {logical_id}:")
            lines.append("    Type: AWS::IAM::Role")
            lines.append("    Properties:")
            lines.append(f"      RoleName: {role_name}")
            lines.append(f"      Path: {role_path}")
            lines.append("      AssumeRolePolicyDocument:")
            lines.append("        Version: '2012-10-17'")
            lines.append("        Statement:")
            lines.append("          - Sid: AAMTrustPolicyStatement")
            lines.append("            Effect: Allow")
            lines.append("            Principal:")
            lines.append("              Service: !Ref TrustServicePrincipal")
            lines.append("            Action:")
            lines.append("              - sts:AssumeRole")
            lines.append("              - sts:SetContext")

            managed = ps.get("aws_managed_policies", [])
            if managed:
                lines.append("      ManagedPolicyArns:")
                for p in managed:
                    lines.append(f"        - {p['arn']}")

            cmp_refs = ps.get("customer_managed_policy_references", [])
            if cmp_refs:
                if not managed:
                    lines.append("      ManagedPolicyArns:")
                for ref in cmp_refs:
                    path = ref.get("path", "/")
                    name = ref["name"]
                    lines.append(f"        - !Sub arn:aws:iam::${{AWS::AccountId}}:policy{path}{name}")

            if ps.get("inline_policy"):
                lines.append("      Policies:")
                lines.append(f"        - PolicyName: {role_name}-inline")
                lines.append("          PolicyDocument:")
                policy_json = json.dumps(ps["inline_policy"], indent=12)
                for j, pline in enumerate(policy_json.split("\n")):
                    lines.append(f"            {pline}")

            lines.append("      Tags:")
            lines.append("        - Key: ManagedBy")
            lines.append("          Value: Truffle-IdC-Migration")
            lines.append(f"        - Key: SourcePermissionSet")
            lines.append(f"          Value: {ps['name']}")

        if aam_application_arn and account_assignments:
            lines.append("")
            lines.append("  # ─── AAM Entitlements ─────────────────────────────────────────")
            for i, a in enumerate(account_assignments):
                ps_arn = a["permission_set_arn"]
                rn = role_map.get(ps_arn, "")
                if not rn:
                    continue
                logical = sanitize(f"{a['principal_display_name']}{a['permission_set_name']}")[:50]
                lines.append("")
                lines.append(f"  Entitlement{logical}{i}:")
                lines.append("    Type: AWS::AccountAccess::Entitlement")
                lines.append("    Properties:")
                lines.append(f"      ApplicationArn: {aam_application_arn}")
                lines.append(f"      RoleArn: !GetAtt {sanitize(a['permission_set_name'])}Role.Arn")
                lines.append(f"      PrincipalType: {a['principal_type']}")
                lines.append(f"      PrincipalId: {a['principal_id']}")

        return "\n".join(lines) + "\n"

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
        with open(cfn_path, "w") as f:
            f.write(content)
        templates[account_id] = {"path": cfn_path, "content": content}

    return {
        "roles_count": len(permission_sets),
        "entitlements_count": len(assignments) if aam_application_arn else 0,
        "templates": templates,
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
    if not cached or not cached.get("data"):
        raise ValueError("No inventory cached. Run discovery first.")

    data = cached["data"]
    permission_sets = data.get("permission_sets", [])
    assignments = data.get("assignments", [])

    role_path = params.get("role_path") or "/aam/"
    role_name_template = params.get("role_name_template") or "AAM-{name}"
    aam_application_arn = params.get("aam_application_arn")

    # Filter to selected permission sets
    selected_ps_arns = params.get("selected_permission_sets")
    if selected_ps_arns:
        permission_sets = [ps for ps in permission_sets if ps["arn"] in selected_ps_arns]
        assignments = [a for a in assignments if a["permission_set_arn"] in selected_ps_arns]

    # Resolve sessions for the target accounts
    session = _resolve_hub_session(params)

    # For multi-account, we need per-account sessions
    auth_method = params.get("auth_method") or "profiles"
    account_sessions: dict = {}

    # Collect unique target accounts from assignments
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
                except Exception:
                    pass
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

    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AAMTrustPolicyStatement",
            "Effect": "Allow",
            "Principal": {"Service": "account-access-preview.amazonaws.com"},
            "Action": ["sts:AssumeRole", "sts:SetContext"],
        }],
    })

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
            iam.create_role(
                RoleName=role_name,
                Path=role_path,
                AssumeRolePolicyDocument=trust_policy,
                Description=f"Created by Truffle IdC-to-AAM for permission set {ps['name']}",
                Tags=[{"Key": "ManagedBy", "Value": "Truffle-IdC-Migration"},
                      {"Key": "SourcePermissionSet", "Value": ps["name"]}],
            )

            # Attach AWS managed policies
            for p in ps.get("aws_managed_policies", []):
                try:
                    iam.attach_role_policy(RoleName=role_name, PolicyArn=p["arn"])
                except Exception:
                    pass

            # Attach CMP references
            for ref in ps.get("customer_managed_policy_references", []):
                path = ref.get("path", "/")
                cmp_arn = f"arn:aws:iam::{acct_id}:policy{path}{ref['name']}"
                try:
                    iam.attach_role_policy(RoleName=role_name, PolicyArn=cmp_arn)
                except Exception:
                    pass

            # Inline policy
            if ps.get("inline_policy"):
                try:
                    iam.put_role_policy(
                        RoleName=role_name,
                        PolicyName=f"{role_name}-inline",
                        PolicyDocument=json.dumps(ps["inline_policy"]),
                    )
                except Exception:
                    pass

            return {
                "role_name": role_name,
                "role_arn": target_arn,
                "account_id": acct_id,
                "permission_set": ps["name"],
                "status": "created",
                "timestamp": _now(),
            }

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
                # AAM is in preview — the GA endpoint doesn't exist yet.
                # Default to the preview endpoint; will be removed once GA lands.
                aam_endpoint_url = params.get("aam_endpoint_url") or f"https://account-access-preview.{aam_region}.api.aws"
                aam_client = session.client("accountaccess", region_name=aam_region, endpoint_url=aam_endpoint_url)
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
