"""
Discover Roles Lambda — discovers IAM roles with SAML trust policies
referencing a specified identity provider in a single account.

Input (from Step Functions):
  {
    "account_id": "123456789012",
    "idp_arn": "arn:aws:iam::123456789012:saml-provider/MyIDP",
    "job_id": "abc123",
    "caller_arn": "arn:aws:iam::...:user/..."
  }

Output:
  {
    "account_id": "123456789012",
    "roles": [...],
    "roles_scanned": 250,
    "status": "ok"
  }
"""

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3

from shared.credentials import assume_role

MAX_WORKERS = 10


def lambda_handler(event, context):
    """Discover SAML-federated roles in one account."""
    account_id = event["account_id"]
    # Accept either idp_arns (list, per-account) or legacy idp_arn (single string)
    idp_arns = event.get("idp_arns", [])
    if not idp_arns:
        legacy = event.get("idp_arn", "")
        if legacy:
            idp_arns = [legacy]

    session = assume_role(account_id, session_suffix="discover")
    iam_client = session.client("iam")
    iam_resource = session.resource("iam")

    # List all roles
    role_names = []
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        role_names.extend(r["RoleName"] for r in page["Roles"])

    discovered_roles = []

    def inspect_role(role_name: str) -> dict | None:
        """Inspect a single role for SAML trust to the target IDP."""
        role = iam_resource.Role(role_name)
        trust_doc = role.assume_role_policy_document
        if not trust_doc:
            return None

        for stmt in trust_doc.get("Statement", []):
            principal = stmt.get("Principal", {})
            federated = principal.get("Federated", "")
            if isinstance(federated, str):
                federated = [federated]

            matched = [a for a in idp_arns if a in federated]
            if matched:
                # Get attached policies
                attached = []
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

                # Get inline policies
                inline = []
                inl_pag = iam_client.get_paginator("list_role_policies")
                for inl_page in inl_pag.paginate(RoleName=role_name):
                    for pname in inl_page.get("PolicyNames", []):
                        inline.append({
                            "policy_name": pname,
                            "policy_type": "Inline",
                        })

                return {
                    "role_name": role_name,
                    "role_arn": f"arn:aws:iam::{account_id}:role/{role_name}",
                    "account_id": account_id,
                    "idp_arns": matched,
                    "trust_policy_document": trust_doc,
                    "policies": attached + inline,
                }

        return None

    # Parallel inspection
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(inspect_role, rn): rn for rn in role_names}
        for fut in as_completed(futures):
            try:
                result = fut.result()
                if result:
                    discovered_roles.append(result)
            except Exception:
                pass

    return {
        "account_id": account_id,
        "roles": discovered_roles,
        "roles_scanned": len(role_names),
        "roles_found": len(discovered_roles),
        "status": "ok",
    }
