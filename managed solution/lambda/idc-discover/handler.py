"""
IdC Discover Lambda — inventories permission sets and assignments from
IAM Identity Center in the hub account.

Input (from Step Functions):
  {
    "account_id": "123456789012",
    "region": "us-west-2",
    "account_scope": "single" | "multi" | "org",
    "target_account_ids": ["123456789012", ...],
    "job_id": "abc123",
    "caller_arn": "arn:aws:iam::...:user/..."
  }

Output:
  {
    "instance_arn": "arn:aws:sso:::instance/ssoins-...",
    "permission_sets": [...],
    "assignments": [...],
    "total_permission_sets": N,
    "total_assignments": N,
    "status": "ok"
  }
"""

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

import boto3
from botocore.config import Config as BotoConfig

from shared.credentials import assume_role

MAX_WORKERS = 5


def lambda_handler(event, context):
    """Discover IdC permission sets and assignments."""
    # The hub_account_id is the management account or delegated admin for
    # Identity Center. IdC APIs only work from this account. The caller
    # must always provide this — we never assume the backend is deployed there.
    hub_account_id = event.get("hub_account_id") or event.get("account_id")
    region = event.get("region", "us-east-1")
    account_scope = event.get("account_scope", "single")
    target_account_ids = event.get("target_account_ids", [hub_account_id])

    # Always AssumeRole into the IdC hub account. The TruffleRole in that
    # account must have SSO/IdentityStore permissions.
    session = assume_role(hub_account_id, session_suffix="idc-discover")

    boto_cfg = BotoConfig(
        retries={"mode": "adaptive", "max_attempts": 5},
        max_pool_connections=10,
    )
    sso_admin = session.client("sso-admin", region_name=region, config=boto_cfg)
    identity_store = session.client("identitystore", region_name=region, config=boto_cfg)

    # Discover IdC instance
    instances = []
    paginator = sso_admin.get_paginator("list_instances")
    for page in paginator.paginate():
        instances.extend(page.get("Instances", []))

    if not instances:
        return {
            "status": "error",
            "error": "No IAM Identity Center instance found",
            "permission_sets": [],
            "assignments": [],
            "total_permission_sets": 0,
            "total_assignments": 0,
        }

    instance_arn = instances[0]["InstanceArn"]
    identity_store_id = instances[0]["IdentityStoreId"]

    # List permission sets
    if account_scope == "org":
        target_accounts = None
    else:
        target_accounts = target_account_ids or [account_id]

    if target_accounts is not None:
        ps_arns_set = set()
        for acct in target_accounts:
            try:
                pag = sso_admin.get_paginator("list_permission_sets_provisioned_to_account")
                for page in pag.paginate(InstanceArn=instance_arn, AccountId=acct):
                    ps_arns_set.update(page.get("PermissionSets", []))
            except Exception:
                pass
        ps_arns = sorted(ps_arns_set)
    else:
        ps_arns = []
        pag = sso_admin.get_paginator("list_permission_sets")
        for page in pag.paginate(InstanceArn=instance_arn):
            ps_arns.extend(page.get("PermissionSets", []))

    # Describe permission sets (parallel)
    permission_sets = []
    _lock = Lock()

    def describe_ps(ps_arn):
        try:
            desc = sso_admin.describe_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=ps_arn
            )
            ps = desc["PermissionSet"]
        except Exception:
            ps = {"Name": ps_arn.rsplit("/", 1)[-1], "PermissionSetArn": ps_arn}

        # Inline policy
        inline_policy = None
        try:
            resp = sso_admin.get_inline_policy_for_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=ps_arn
            )
            if resp.get("InlinePolicy"):
                inline_policy = json.loads(resp["InlinePolicy"])
        except Exception:
            pass

        # AWS managed policies
        aws_managed = []
        try:
            pag = sso_admin.get_paginator("list_managed_policies_in_permission_set")
            for page in pag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                for p in page.get("AttachedManagedPolicies", []):
                    aws_managed.append({"name": p.get("Name", ""), "arn": p.get("Arn", "")})
        except Exception:
            pass

        # Customer managed policy references
        cmp_refs = []
        try:
            pag = sso_admin.get_paginator("list_customer_managed_policy_references_in_permission_set")
            for page in pag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                for ref in page.get("CustomerManagedPolicyReferences", []):
                    cmp_refs.append({"name": ref.get("Name", ""), "path": ref.get("Path", "/")})
        except Exception:
            pass

        return {
            "arn": ps_arn,
            "name": ps.get("Name", ps_arn.rsplit("/", 1)[-1]),
            "description": ps.get("Description", ""),
            "session_duration": ps.get("SessionDuration", "PT1H"),
            "inline_policy": inline_policy,
            "aws_managed_policies": aws_managed,
            "customer_managed_policy_references": cmp_refs,
        }

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(describe_ps, arn) for arn in ps_arns]
        for fut in as_completed(futures):
            try:
                permission_sets.append(fut.result())
            except Exception:
                pass

    # List assignments (parallel per permission set)
    ps_name_map = {ps["arn"]: ps["name"] for ps in permission_sets}
    assignments = []
    name_cache = {}
    _name_lock = Lock()

    def resolve_name(principal_type, principal_id):
        key = (principal_type, principal_id)
        with _name_lock:
            if key in name_cache:
                return name_cache[key]
        try:
            if principal_type == "USER":
                resp = identity_store.describe_user(
                    IdentityStoreId=identity_store_id, UserId=principal_id
                )
                name = resp.get("UserName") or resp.get("DisplayName") or principal_id
            else:
                resp = identity_store.describe_group(
                    IdentityStoreId=identity_store_id, GroupId=principal_id
                )
                name = resp.get("DisplayName") or resp.get("GroupName") or principal_id
        except Exception:
            name = principal_id
        with _name_lock:
            name_cache[key] = name
        return name

    def fetch_assignments(ps_arn):
        results = []
        if target_accounts is not None:
            accounts_for_ps = target_accounts
        else:
            accounts_for_ps = []
            try:
                pag = sso_admin.get_paginator("list_accounts_for_provisioned_permission_set")
                for page in pag.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                    accounts_for_ps.extend(page.get("AccountIds", []))
            except Exception:
                pass

        for acct in accounts_for_ps:
            try:
                pag = sso_admin.get_paginator("list_account_assignments")
                for page in pag.paginate(
                    InstanceArn=instance_arn, AccountId=acct, PermissionSetArn=ps_arn
                ):
                    for a in page.get("AccountAssignments", []):
                        results.append({
                            "permission_set_arn": ps_arn,
                            "permission_set_name": ps_name_map.get(ps_arn, ""),
                            "account_id": acct,
                            "principal_type": a["PrincipalType"],
                            "principal_id": a["PrincipalId"],
                            "principal_display_name": resolve_name(
                                a["PrincipalType"], a["PrincipalId"]
                            ),
                        })
            except Exception:
                pass
        return results

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(fetch_assignments, arn) for arn in ps_arns]
        for fut in as_completed(futures):
            try:
                assignments.extend(fut.result())
            except Exception:
                pass

    return {
        "instance_arn": instance_arn,
        "identity_store_id": identity_store_id,
        "hub_account_id": hub_account_id,
        "account_scope": account_scope,
        "target_accounts": target_accounts,
        "permission_sets": permission_sets,
        "assignments": assignments,
        "total_permission_sets": len(permission_sets),
        "total_assignments": len(assignments),
        "status": "ok",
    }
