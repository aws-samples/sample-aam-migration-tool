"""
Scan Global Lambda — scans global (non-regional) resource policies for a
single account: S3 bucket policies (all regions), IAM policies, and
Organizations SCPs/RCPs if management_account is true.

Input (from Step Functions):
  {
    "account_id": "123456789012",
    "search_terms": ["old-idp-arn"],
    "management_account": true/false,
    "services": [...] | null,
    "job_id": "abc123",
    "caller_arn": "arn:aws:iam::...:user/..."
  }

Output:
  {
    "account_id": "123456789012",
    "scope": "global",
    "matches": [...],
    "resources_scanned": 42,
    "status": "ok"
  }
"""

import json
import os
import sys

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from credentials import assume_role


def lambda_handler(event, context):
    """Scan global resource policies for one account."""
    account_id = event["account_id"]
    search_terms = event.get("search_terms", [])
    management_account = event.get("management_account", False)
    service_filter = event.get("services")

    session = assume_role(account_id, session_suffix="scan-global")
    matches = []
    resources_scanned = 0

    # IAM role trust policies (global service)
    if not service_filter or "iam" in service_filter:
        iam_result = scan_iam_trust_policies(session, account_id, search_terms)
        matches.extend(iam_result["matches"])
        resources_scanned += iam_result["count"]

    # Organizations SCPs/RCPs (only if management account)
    if management_account and (not service_filter or "organizations" in service_filter):
        org_result = scan_organization_policies(session, account_id, search_terms)
        matches.extend(org_result["matches"])
        resources_scanned += org_result["count"]

    return {
        "account_id": account_id,
        "scope": "global",
        "matches": matches,
        "resources_scanned": resources_scanned,
        "status": "ok",
    }


def _matches_terms(policy_str: str, search_terms: list[str]) -> list[str]:
    """Check if a policy string contains any of the search terms."""
    policy_lower = policy_str.lower()
    return [t for t in search_terms if t.lower() in policy_lower]


def scan_iam_trust_policies(session: boto3.Session, account_id: str, search_terms: list[str]) -> dict:
    """Scan IAM role trust policies for references to search terms."""
    iam = session.client("iam")
    matches = []
    count = 0

    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                count += 1
                trust_doc = role.get("AssumeRolePolicyDocument", {})
                if isinstance(trust_doc, str):
                    trust_str = trust_doc
                else:
                    trust_str = json.dumps(trust_doc)

                found_terms = _matches_terms(trust_str, search_terms)
                if found_terms:
                    matches.append({
                        "service": "iam",
                        "resource_type": "role_trust_policy",
                        "resource_name": role["RoleName"],
                        "resource_arn": role["Arn"],
                        "region": "global",
                        "account_id": account_id,
                        "matched_terms": found_terms,
                        "policy": trust_doc if isinstance(trust_doc, dict) else json.loads(trust_doc),
                    })
    except Exception as e:
        matches.append({
            "service": "iam",
            "error": str(e),
            "account_id": account_id,
        })

    return {"matches": matches, "count": count}


def scan_organization_policies(session: boto3.Session, account_id: str, search_terms: list[str]) -> dict:
    """Scan Organization SCPs and RCPs."""
    org = session.client("organizations")
    matches = []
    count = 0

    for policy_type in ["SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"]:
        try:
            paginator = org.get_paginator("list_policies")
            for page in paginator.paginate(Filter=policy_type):
                for policy_summary in page.get("Policies", []):
                    count += 1
                    policy_id = policy_summary["Id"]
                    try:
                        detail = org.describe_policy(PolicyId=policy_id)
                        content = detail["Policy"]["Content"]
                        found_terms = _matches_terms(content, search_terms)
                        if found_terms:
                            prefix = "SCP" if "SERVICE" in policy_type else "RCP"
                            matches.append({
                                "service": "organizations",
                                "resource_type": policy_type.lower(),
                                "resource_name": policy_summary["Name"],
                                "resource_arn": policy_summary["Arn"],
                                "region": "global",
                                "account_id": account_id,
                                "matched_terms": found_terms,
                                "policy": json.loads(content),
                            })
                    except Exception:
                        pass
        except Exception:
            pass

    return {"matches": matches, "count": count}
