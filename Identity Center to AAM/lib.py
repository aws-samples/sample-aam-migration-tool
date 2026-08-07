"""
IdC → AAM — Core Library.

Stateless functions that both the CLI (idc_to_aam.py) and the UI adapter
(ui/backend/idc.py) can import. Single source of truth for discovery,
role creation, and entitlement logic.

All functions accept explicit boto3 clients/sessions and return data.
No global state, no interactive prompts, no print statements.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, BotoCoreError

ProgressCb = Callable[[dict], None]

AAM_ENDPOINT_TEMPLATE = "https://account-access.{region}.api.aws"


def build_aam_trust_policy(aam_source_account: str = "", aam_application_arn: str = "") -> dict:
    """
    Build the standard AAM trust policy document with optional confused-deputy conditions.

    When aam_source_account and aam_application_arn are provided, adds
    aws:SourceAccount and aws:SourceArn conditions to prevent confused-deputy attacks.
    """
    stmt: dict = {
        "Sid": "AAMTrustPolicyStatement",
        "Effect": "Allow",
        "Principal": {"Service": "account-access.amazonaws.com"},
        "Action": ["sts:AssumeRole", "sts:SetContext"],
    }
    if aam_source_account or aam_application_arn:
        condition: dict = {"StringEquals": {}}
        if aam_source_account:
            condition["StringEquals"]["aws:SourceAccount"] = aam_source_account
        if aam_application_arn:
            condition["StringEquals"]["aws:SourceArn"] = aam_application_arn
        stmt["Condition"] = condition
    return {
        "Version": "2012-10-17",
        "Statement": [stmt],
    }


# ─── IdC Instance Discovery ──────────────────────────────────────────────────

def discover_idc_instance(sso_admin_client) -> Tuple[str, str]:
    """Discover the IdC instance. Returns (instance_arn, identity_store_id)."""
    instances = []
    paginator = sso_admin_client.get_paginator("list_instances")
    for page in paginator.paginate():
        instances.extend(page.get("Instances", []))
    if not instances:
        raise RuntimeError("No IAM Identity Center instance found")
    return instances[0]["InstanceArn"], instances[0]["IdentityStoreId"]


# ─── Permission Set Listing ───────────────────────────────────────────────────

def list_permission_sets_for_account(
    sso_admin_client, instance_arn: str, account_id: str
) -> List[str]:
    """List permission sets provisioned to a specific account (optimized path)."""
    arns = []
    pag = sso_admin_client.get_paginator("list_permission_sets_provisioned_to_account")
    for page in pag.paginate(InstanceArn=instance_arn, AccountId=account_id):
        arns.extend(page.get("PermissionSets", []))
    return arns


def list_all_permission_sets(sso_admin_client, instance_arn: str) -> List[str]:
    """List all permission sets in the IdC instance (org mode)."""
    arns = []
    pag = sso_admin_client.get_paginator("list_permission_sets")
    for page in pag.paginate(InstanceArn=instance_arn):
        arns.extend(page.get("PermissionSets", []))
    return arns


# ─── Permission Set Description ───────────────────────────────────────────────

def fetch_permission_set_policies(
    sso_admin_client, instance_arn: str, ps_arn: str, ps_name: str = ""
) -> Dict[str, Any]:
    """Fetch only the policies for a permission set (skips DescribePermissionSet).

    Use when you already have the ARN and name (e.g., from a migration plan CSV)
    and only need the policy details for role creation/CFN generation.
    """
    # Inline policy
    inline_policy = None
    try:
        inline_resp = sso_admin_client.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=ps_arn
        )
        if inline_resp.get("InlinePolicy"):
            inline_policy = json.loads(inline_resp["InlinePolicy"])
    except Exception:
        pass

    # AWS managed policies
    aws_managed = []
    try:
        mp_pag = sso_admin_client.get_paginator("list_managed_policies_in_permission_set")
        for page in mp_pag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
            for p in page.get("AttachedManagedPolicies", []):
                aws_managed.append({"name": p.get("Name", ""), "arn": p.get("Arn", "")})
    except Exception:
        pass

    # Customer managed policy references
    cmp_refs = []
    try:
        cmp_pag = sso_admin_client.get_paginator("list_customer_managed_policy_references_in_permission_set")
        for page in cmp_pag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
            for ref in page.get("CustomerManagedPolicyReferences", []):
                cmp_refs.append({"name": ref.get("Name", ""), "path": ref.get("Path", "/")})
    except Exception:
        pass

    # Permission boundary
    permission_boundary = None
    try:
        pb_resp = sso_admin_client.get_permissions_boundary_for_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=ps_arn
        )
        if pb_resp.get("PermissionsBoundary"):
            permission_boundary = pb_resp["PermissionsBoundary"]
    except Exception:
        pass

    return {
        "arn": ps_arn,
        "name": ps_name or ps_arn.rsplit("/", 1)[-1],
        "description": "",
        "session_duration": "PT1H",
        "inline_policy": inline_policy,
        "aws_managed_policies": aws_managed,
        "customer_managed_policy_references": cmp_refs,
        "permission_boundary": permission_boundary,
    }


def describe_permission_set(
    sso_admin_client, instance_arn: str, ps_arn: str
) -> Dict[str, Any]:
    """Fully describe a permission set including policies. Returns a flat dict."""
    try:
        desc_resp = sso_admin_client.describe_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=ps_arn
        )
        ps = desc_resp["PermissionSet"]
    except Exception:
        ps = {"Name": ps_arn.rsplit("/", 1)[-1], "PermissionSetArn": ps_arn}

    # Inline policy
    inline_policy = None
    try:
        inline_resp = sso_admin_client.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=ps_arn
        )
        if inline_resp.get("InlinePolicy"):
            inline_policy = json.loads(inline_resp["InlinePolicy"])
    except Exception:
        pass

    # AWS managed policies
    aws_managed = []
    try:
        mp_pag = sso_admin_client.get_paginator("list_managed_policies_in_permission_set")
        for page in mp_pag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
            for p in page.get("AttachedManagedPolicies", []):
                aws_managed.append({"name": p.get("Name", ""), "arn": p.get("Arn", "")})
    except Exception:
        pass

    # Customer managed policy references
    cmp_refs = []
    try:
        cmp_pag = sso_admin_client.get_paginator("list_customer_managed_policy_references_in_permission_set")
        for page in cmp_pag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
            for ref in page.get("CustomerManagedPolicyReferences", []):
                cmp_refs.append({"name": ref.get("Name", ""), "path": ref.get("Path", "/")})
    except Exception:
        pass

    # Permission boundary
    permission_boundary = None
    try:
        pb_resp = sso_admin_client.get_permissions_boundary_for_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=ps_arn
        )
        if pb_resp.get("PermissionsBoundary"):
            permission_boundary = pb_resp["PermissionsBoundary"]
    except Exception:
        # ResourceNotFoundException is normal (no boundary set)
        pass

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


def describe_permission_sets_parallel(
    sso_admin_client, instance_arn: str, ps_arns: List[str], workers: int = 5,
    on_progress: Optional[ProgressCb] = None,
) -> List[Dict[str, Any]]:
    """Describe multiple permission sets in parallel."""
    results = []
    _lock = Lock()
    done = [0]
    total = len(ps_arns)

    def describe_one(arn: str) -> Dict[str, Any]:
        r = describe_permission_set(sso_admin_client, instance_arn, arn)
        with _lock:
            done[0] += 1
            if on_progress and (done[0] % 5 == 0 or done[0] == total):
                on_progress({"completed_units": done[0], "total_units": total, "phase": "describe"})
        return r

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(describe_one, arn) for arn in ps_arns]
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                pass
    return results


# ─── Assignments ──────────────────────────────────────────────────────────────

def list_assignments_for_permission_set(
    sso_admin_client,
    identity_store_client,
    instance_arn: str,
    ps_arn: str,
    identity_store_id: str,
    filter_account_ids: Optional[List[str]] = None,
    name_cache: Optional[dict] = None,
    name_lock: Optional[Lock] = None,
) -> List[Dict[str, Any]]:
    """
    List assignments for a permission set. Optionally filter to specific accounts.
    Resolves principal display names.
    """
    if name_cache is None:
        name_cache = {}
    if name_lock is None:
        name_lock = Lock()

    def resolve_name(principal_type: str, principal_id: str) -> str:
        key = (principal_type, principal_id)
        with name_lock:
            if key in name_cache:
                return name_cache[key]
        try:
            if principal_type == "USER":
                resp = identity_store_client.describe_user(
                    IdentityStoreId=identity_store_id, UserId=principal_id
                )
                name = resp.get("UserName") or resp.get("DisplayName") or principal_id
            else:
                resp = identity_store_client.describe_group(
                    IdentityStoreId=identity_store_id, GroupId=principal_id
                )
                name = resp.get("DisplayName") or resp.get("GroupName") or principal_id
        except Exception:
            name = principal_id
        with name_lock:
            name_cache[key] = name
        return name

    # Determine accounts to query
    if filter_account_ids is not None:
        accounts = filter_account_ids
    else:
        accounts = []
        try:
            apag = sso_admin_client.get_paginator("list_accounts_for_provisioned_permission_set")
            for page in apag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                accounts.extend(page.get("AccountIds", []))
        except Exception:
            pass

    results = []
    for acct in accounts:
        try:
            asg_pag = sso_admin_client.get_paginator("list_account_assignments")
            for page in asg_pag.paginate(
                InstanceArn=instance_arn, AccountId=acct, PermissionSetArn=ps_arn
            ):
                for a in page.get("AccountAssignments", []):
                    principal_type = a["PrincipalType"]
                    principal_id = a["PrincipalId"]
                    results.append({
                        "permission_set_arn": ps_arn,
                        "account_id": acct,
                        "principal_type": principal_type,
                        "principal_id": principal_id,
                        "principal_display_name": resolve_name(principal_type, principal_id),
                    })
        except Exception:
            pass

    return results


def list_assignments_parallel(
    sso_admin_client,
    identity_store_client,
    instance_arn: str,
    ps_arns: List[str],
    identity_store_id: str,
    filter_account_ids: Optional[List[str]] = None,
    workers: int = 5,
    on_progress: Optional[ProgressCb] = None,
) -> List[Dict[str, Any]]:
    """List assignments for multiple permission sets in parallel."""
    all_assignments = []
    _lock = Lock()
    name_cache: dict = {}
    name_lock = Lock()
    done = [0]
    total = len(ps_arns)

    def fetch_one(ps_arn: str) -> List[Dict[str, Any]]:
        r = list_assignments_for_permission_set(
            sso_admin_client, identity_store_client, instance_arn, ps_arn,
            identity_store_id, filter_account_ids, name_cache, name_lock,
        )
        with _lock:
            done[0] += 1
            if on_progress and (done[0] % 5 == 0 or done[0] == total):
                on_progress({"completed_units": done[0], "total_units": total, "phase": "assignments"})
        return r

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(fetch_one, arn) for arn in ps_arns]
        for fut in as_completed(futures):
            try:
                all_assignments.extend(fut.result())
            except Exception:
                pass

    return all_assignments


# ─── Role Creation ────────────────────────────────────────────────────────────

def create_role(
    iam_client,
    role_name: str,
    role_path: str,
    trust_policy_json: str,
    permission_set: Dict[str, Any],
    account_id: str,
    tags: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Create an IAM role matching a permission set. Idempotent (skips if exists).
    Returns result dict with status + any warnings.
    """
    target_arn = f"arn:aws:iam::{account_id}:role{role_path}{role_name}"
    warnings: List[str] = []

    try:
        # Idempotency check
        try:
            iam_client.get_role(RoleName=role_name)
            return {
                "role_name": role_name,
                "role_arn": target_arn,
                "account_id": account_id,
                "permission_set": permission_set.get("name", ""),
                "status": "already exists",
            }
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

        # Create
        create_tags = tags or [
            {"Key": "ManagedBy", "Value": "Truffle-IdC-Migration"},
            {"Key": "SourcePermissionSet", "Value": permission_set.get("name", "")},
        ]
        iam_client.create_role(
            RoleName=role_name,
            Path=role_path,
            AssumeRolePolicyDocument=trust_policy_json,
            Description=f"Created by Truffle for permission set {permission_set.get('name', '')}",
            Tags=create_tags,
        )

        # Attach AWS managed policies
        for p in permission_set.get("aws_managed_policies", []):
            try:
                iam_client.attach_role_policy(RoleName=role_name, PolicyArn=p["arn"])
            except Exception as exc:
                warnings.append(f"Failed to attach managed policy {p['arn']}: {exc}")

        # Attach CMP references
        for ref in permission_set.get("customer_managed_policy_references", []):
            path = ref.get("path", "/")
            cmp_arn = f"arn:aws:iam::{account_id}:policy{path}{ref['name']}"
            try:
                iam_client.attach_role_policy(RoleName=role_name, PolicyArn=cmp_arn)
            except Exception as exc:
                warnings.append(f"Failed to attach CMP {cmp_arn}: {exc}")

        # Inline policy
        if permission_set.get("inline_policy"):
            try:
                iam_client.put_role_policy(
                    RoleName=role_name,
                    PolicyName=f"{role_name}-inline",
                    PolicyDocument=json.dumps(permission_set["inline_policy"]),
                )
            except Exception as exc:
                warnings.append(f"Failed to attach inline policy: {exc}")

        # Permission boundary
        if permission_set.get("permission_boundary"):
            pb = permission_set["permission_boundary"]
            # Permission boundary can be a managed policy ARN or a customer managed policy reference
            pb_arn = ""
            if pb.get("ManagedPolicyArn"):
                pb_arn = pb["ManagedPolicyArn"]
            elif pb.get("CustomerManagedPolicyReference"):
                ref = pb["CustomerManagedPolicyReference"]
                pb_path = ref.get("Path", "/")
                pb_name = ref.get("Name", "")
                pb_arn = f"arn:aws:iam::{account_id}:policy{pb_path}{pb_name}"
            if pb_arn:
                try:
                    iam_client.put_role_permissions_boundary(
                        RoleName=role_name,
                        PermissionsBoundary=pb_arn,
                    )
                except Exception as exc:
                    warnings.append(f"Failed to set permission boundary {pb_arn}: {exc}")

        result = {
            "role_name": role_name,
            "role_arn": target_arn,
            "account_id": account_id,
            "permission_set": permission_set.get("name", ""),
            "status": "created",
        }
        if warnings:
            result["warnings"] = warnings
            result["error"] = f"{len(warnings)} policy attach failure(s)"
        return result

    except Exception as exc:
        return {
            "role_name": role_name,
            "role_arn": "",
            "account_id": account_id,
            "permission_set": permission_set.get("name", ""),
            "status": "error",
            "error": str(exc),
        }


# ─── AAM Entitlement Creation ────────────────────────────────────────────────

def create_entitlements(
    hub_session: boto3.Session,
    aam_application_arn: str,
    assignments: List[Dict[str, Any]],
    role_arn_lookup: Dict[str, str],
    region: str = "us-east-1",
    workers: int = 5,
    on_progress: Optional[ProgressCb] = None,
) -> List[Dict[str, Any]]:
    """
    Create AAM entitlements for assignments.

    role_arn_lookup: {permission_set_arn#account_id: role_arn}
    Uses preview endpoint, retries on ValidationException.
    """
    aam_endpoint = AAM_ENDPOINT_TEMPLATE.format(region=region)
    try:
        aam_client = hub_session.client("accountaccess", region_name=region, endpoint_url=aam_endpoint)
    except Exception as exc:
        return [{"status": "error", "error": f"AAM client unavailable: {exc}"} for _ in assignments]

    results = []
    _lock = Lock()
    completed = [0]
    total = len(assignments)

    def create_one(a: Dict[str, Any]) -> Dict[str, Any]:
        key = f"{a['permission_set_arn']}#{a['account_id']}"
        role_arn = role_arn_lookup.get(key, "")
        if not role_arn:
            return {"principal": a.get("principal_display_name", ""), "status": "skipped", "error": "No role ARN"}

        principal_type = a["principal_type"]
        principal_id = a["principal_id"]
        principal_block = {"userId": principal_id} if principal_type == "USER" else {"groupId": principal_id}

        max_retries = 3
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
                return {
                    "principal": a.get("principal_display_name", ""),
                    "principal_type": principal_type,
                    "account_id": a["account_id"],
                    "role_arn": role_arn,
                    "entitlement_id": resp.get("entitlementId", ""),
                    "status": "created",
                }
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in ("ConflictException",) or "AlreadyExists" in str(exc):
                    return {"principal": a.get("principal_display_name", ""), "role_arn": role_arn, "status": "already exists"}
                if code == "ValidationException" and attempt < max_retries - 1:
                    time.sleep(3 * (attempt + 1))
                else:
                    return {"principal": a.get("principal_display_name", ""), "role_arn": role_arn, "status": "error", "error": str(exc)}
            except Exception as exc:
                return {"principal": a.get("principal_display_name", ""), "role_arn": role_arn, "status": "error", "error": str(exc)}
        return {"principal": a.get("principal_display_name", ""), "status": "error", "error": "Exhausted retries"}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(create_one, a) for a in assignments]
        for fut in as_completed(futures):
            result = fut.result()
            results.append(result)
            with _lock:
                completed[0] += 1
                if on_progress:
                    on_progress({"completed_units": completed[0], "total_units": total, "message": f"Entitlement {completed[0]}/{total}"})

    return results
