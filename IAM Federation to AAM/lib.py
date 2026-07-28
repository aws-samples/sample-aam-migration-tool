"""
IAM Federation → AAM — Core Library.

Stateless functions that both the CLI (AAM_role_evaluation.py) and the UI
adapter (ui/backend/iam_federation.py) import. Single source of truth for
all discovery, migration, and entitlement logic.

All functions accept a boto3 Session (or client) and return data. No global
state, no interactive prompts, no print statements.
"""

from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Any, Callable, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

# ─── Constants ────────────────────────────────────────────────────────────────

NEW_TRUST_STATEMENT = {
    "Sid": "AAMTrustPolicyStatement",
    "Effect": "Allow",
    "Principal": {
        "Service": "account-access.amazonaws.com"
    },
    "Action": [
        "sts:AssumeRole",
        "sts:SetContext"
    ],
}

# Both the preview and GA service principals — used for idempotency detection
AAM_SERVICE_PRINCIPALS = {"account-access.amazonaws.com", "account-access-preview.amazonaws.com"}

AAM_ENDPOINT_TEMPLATE = "https://account-access.{region}.api.aws"

ProgressCb = Callable[[dict], None]


# ─── Discovery ────────────────────────────────────────────────────────────────

def list_saml_providers(session: boto3.Session) -> List[Dict[str, str]]:
    """List SAML identity providers in the account. Returns list of {arn, name, is_identity_center}."""
    iam = session.client("iam")
    response = iam.list_saml_providers()
    providers = []
    for p in response.get("SAMLProviderList", []):
        arn = p["Arn"]
        name = arn.split("/")[-1]
        providers.append({
            "arn": arn,
            "name": name,
            "is_identity_center": "AWSSSO" in name or "DO_NOT_DELETE" in name,
        })
    return providers


def list_all_role_names(session: boto3.Session) -> List[str]:
    """Paginate through all IAM roles and return their names."""
    iam = session.client("iam")
    names = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        names.extend(r["RoleName"] for r in page["Roles"])
    return names


def discover_federated_roles(
    session: boto3.Session,
    role_names: List[str],
    idp_arns: List[str] | str,
    account_id: str,
    workers: int = 5,
    on_progress: Optional[ProgressCb] = None,
) -> List[Dict[str, Any]]:
    """
    Filter IAM roles to those with SAML trust policies referencing any of the
    provided idp_arns. Parallelized. Single pass through all roles.

    idp_arns: a single ARN string or a list of ARNs to match against.
    Returns list of role dicts with trust_policy_document and policies.
    """
    # Normalize to list
    if isinstance(idp_arns, str):
        idp_arns = [idp_arns]
    idp_set = set(idp_arns)

    iam_client = session.client("iam")
    iam_resource = session.resource("iam")
    results: List[Dict[str, Any]] = []
    _lock = Lock()
    scanned = [0]
    total = len(role_names)

    def inspect_role(role_name: str) -> Optional[Dict[str, Any]]:
        role = iam_resource.Role(role_name)
        trust_doc = role.assume_role_policy_document
        if not trust_doc:
            return None

        for stmt in trust_doc.get("Statement", []):
            principal = stmt.get("Principal", {})
            federated = principal.get("Federated", "")
            if isinstance(federated, str):
                federated = [federated]
            # Match if ANY of the provided IDPs appear in the trust
            matched_idps = [a for a in federated if a in idp_set]
            if matched_idps:
                # Get attached policies
                attached = []
                try:
                    att_pag = iam_client.get_paginator("list_attached_role_policies")
                    for att_page in att_pag.paginate(RoleName=role_name):
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
                except Exception:
                    pass

                # Get inline policies
                inline = []
                try:
                    inl_pag = iam_client.get_paginator("list_role_policies")
                    for inl_page in inl_pag.paginate(RoleName=role_name):
                        for pname in inl_page.get("PolicyNames", []):
                            inline.append({"policy_name": pname, "policy_type": "Inline"})
                except Exception:
                    pass

                # Trust policy summary
                trust_summary = []
                for s in trust_doc.get("Statement", []):
                    fed = s.get("Principal", {}).get("Federated", "")
                    if isinstance(fed, list):
                        fed = ", ".join(fed)
                    if fed:
                        provider_name = fed.split("/")[-1] if "/" in fed else fed
                        trust_summary.append(f"Federated:{provider_name}")

                return {
                    "role_name": role_name,
                    "role_arn": f"arn:aws:iam::{account_id}:role/{role_name}",
                    "account_id": account_id,
                    "idp_arns": matched_idps,
                    "trust_policy_document": trust_doc,
                    "trust_summary": "; ".join(trust_summary),
                    "policies": attached + inline,
                }
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(inspect_role, rn): rn for rn in role_names}
        for fut in as_completed(futures):
            with _lock:
                scanned[0] += 1
                if on_progress and scanned[0] % 10 == 0:
                    on_progress({
                        "roles_scanned": scanned[0],
                        "roles_total": total,
                        "message": f"Inspected {scanned[0]}/{total} roles",
                    })
            try:
                result = fut.result()
                if result:
                    results.append(result)
            except Exception:
                pass

    return results


# ─── Trust Policy Migration ───────────────────────────────────────────────────

def migrate_trust_policy(
    session: boto3.Session,
    role_name: str,
    mode: str,
    idp_arn: str,
) -> Dict[str, Any]:
    """
    Update a single role's trust policy. Returns a result dict.

    mode: "ADD" — append AAM statement alongside existing.
          "REPLACE" — remove IDP statements, add AAM statement.
    """
    iam_client = session.client("iam")

    try:
        role_resp = iam_client.get_role(RoleName=role_name)
        trust_doc = role_resp["Role"]["AssumeRolePolicyDocument"]

        # Check if already migrated — look for AAM service principal in any statement
        for stmt in trust_doc.get("Statement", []):
            principal = stmt.get("Principal", {})
            service = principal.get("Service", "")
            if isinstance(service, str):
                service = [service]
            if any(s in AAM_SERVICE_PRINCIPALS for s in service):
                return {
                    "role_name": role_name,
                    "status": "skipped",
                    "reason": "Already has AAM service principal in trust policy",
                }

        # Build new trust policy
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

        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(new_doc),
        )

        return {
            "role_name": role_name,
            "status": "success",
            "mode": mode,
            "previous_trust_policy": trust_doc,
        }

    except Exception as exc:
        return {
            "role_name": role_name,
            "status": "error",
            "error": str(exc),
        }


def migrate_roles_parallel(
    session_map: Dict[str, boto3.Session],
    role_arns: List[str],
    mode: str,
    idp_arn: str,
    workers: int = 5,
    on_progress: Optional[ProgressCb] = None,
) -> List[Dict[str, Any]]:
    """
    Migrate trust policies on multiple roles in parallel.

    session_map: {account_id: session} for routing each role to the right account.
    role_arns: list of full role ARNs to migrate.
    """
    results: List[Dict[str, Any]] = []
    _lock = Lock()
    completed = [0]
    total = len(role_arns)

    def migrate_one(role_arn: str) -> Dict[str, Any]:
        parts = role_arn.split(":")
        account_id = parts[4] if len(parts) >= 5 else ""
        role_name = role_arn.split("/")[-1]

        session = session_map.get(account_id)
        if not session:
            # Fallback to first available session
            session = next(iter(session_map.values()), None)
        if not session:
            return {"role_arn": role_arn, "role_name": role_name, "status": "error", "error": "No session available"}

        result = migrate_trust_policy(session, role_name, mode, idp_arn)
        result["role_arn"] = role_arn
        result["account_id"] = account_id
        return result

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(migrate_one, arn): arn for arn in role_arns}
        for fut in as_completed(futures):
            result = fut.result()
            results.append(result)
            with _lock:
                completed[0] += 1
                if on_progress:
                    on_progress({
                        "completed_units": completed[0],
                        "total_units": total,
                        "message": f"{result.get('status', '').title()}: {result.get('role_name', '')}",
                    })

    return results


# ─── Entitlement Creation ─────────────────────────────────────────────────────

def create_entitlements(
    hub_session: boto3.Session,
    aam_application_arn: str,
    mappings: List[Dict[str, str]],
    region: str = "us-east-1",
    workers: int = 5,
    on_progress: Optional[ProgressCb] = None,
) -> List[Dict[str, Any]]:
    """
    Create AAM entitlements from explicit columnar mappings.

    Each mapping: {group, account, role, matchedRoleArn}
    Uses the preview endpoint by default.
    """
    aam_endpoint = AAM_ENDPOINT_TEMPLATE.format(region=region)
    try:
        aam_client = hub_session.client("accountaccess", region_name=region, endpoint_url=aam_endpoint)
    except Exception as exc:
        return [{"group": m.get("group", ""), "status": "error", "error": f"AAM client unavailable: {exc}"} for m in mappings]

    results: List[Dict[str, Any]] = []
    _lock = Lock()
    completed = [0]
    total = len(mappings)

    def create_one(m: Dict[str, str]) -> Dict[str, Any]:
        role_arn = m.get("matchedRoleArn") or ""
        principal_id = m.get("principal") or m.get("group") or ""
        principal_type = m.get("principal_type", "GROUP")

        if not role_arn or not principal_id:
            return {"group": m.get("group", ""), "status": "skipped", "error": "Missing role ARN or principal"}

        principal_block: dict = {}
        if principal_type.upper() == "USER":
            principal_block["userId"] = principal_id
        else:
            principal_block["groupId"] = principal_id

        # Retry on ValidationException (IAM propagation delay)
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
                    "group": m.get("group", ""),
                    "principal": principal_id,
                    "account": m.get("account", ""),
                    "role": m.get("role", ""),
                    "role_arn": role_arn,
                    "entitlement_id": resp.get("entitlementId", ""),
                    "status": "created",
                }
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code == "ConflictException" or "AlreadyExists" in str(exc):
                    return {
                        "group": m.get("group", ""),
                        "principal": principal_id,
                        "account": m.get("account", ""),
                        "role_arn": role_arn,
                        "status": "already exists",
                    }
                if code == "ValidationException" and attempt < max_retries - 1:
                    time.sleep(3 * (attempt + 1))
                else:
                    return {
                        "group": m.get("group", ""),
                        "principal": principal_id,
                        "account": m.get("account", ""),
                        "role_arn": role_arn,
                        "status": "error",
                        "error": str(exc),
                    }
            except Exception as exc:
                return {
                    "group": m.get("group", ""),
                    "principal": principal_id,
                    "role_arn": role_arn,
                    "status": "error",
                    "error": str(exc),
                }
        # Should not reach here
        return {"group": m.get("group", ""), "status": "error", "error": "Exhausted retries"}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(create_one, m): m for m in mappings}
        for fut in as_completed(futures):
            result = fut.result()
            results.append(result)
            with _lock:
                completed[0] += 1
                if on_progress:
                    on_progress({
                        "completed_units": completed[0],
                        "total_units": total,
                        "message": f"Entitlement {completed[0]}/{total}",
                    })

    return results


# ─── Entitlement CSV Parsing ──────────────────────────────────────────────────

def parse_entitlement_csv(csv_path: str) -> List[Dict[str, str]]:
    """
    Parse a columnar entitlement CSV with columns: Group/Principal, Account ID, Role Name, Role ARN.
    Returns list of mapping dicts.
    """
    import csv

    mappings = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Flexible column name matching
            group = ""
            account = ""
            role = ""
            role_arn = ""
            for key, val in row.items():
                key_lower = key.lower().strip()
                if "group" in key_lower or "principal" in key_lower:
                    group = (val or "").strip()
                elif "account" in key_lower:
                    account = (val or "").strip()
                elif "role arn" in key_lower or key_lower == "role_arn":
                    role_arn = (val or "").strip()
                elif "role" in key_lower:
                    role = (val or "").strip()

            if not account and not role:
                continue

            if not role_arn and account and role:
                role_arn = f"arn:aws:iam::{account}:role/{role}"

            mappings.append({
                "group": group,
                "principal": group,
                "account": account,
                "role": role,
                "matchedRoleArn": role_arn,
            })

    return mappings
