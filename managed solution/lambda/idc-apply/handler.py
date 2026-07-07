"""
IdC Apply Lambda — creates a single IAM role with AAM trust policy and
attaches policies from the corresponding permission set. Optionally creates
an AAM entitlement.

Invoked once per (permission_set, account) pair by the IdC Apply Step Functions
workflow.

Input (from Step Functions):
  {
    "permission_set": {
      "arn": "arn:aws:sso:::permissionSet/...",
      "name": "AdminAccess",
      "aws_managed_policies": [{"name": "...", "arn": "..."}],
      "customer_managed_policy_references": [{"name": "...", "path": "/"}],
      "inline_policy": {...} | null
    },
    "account_id": "123456789012",
    "role_path": "/aam/",
    "role_name_template": "AAM-{name}",
    "aam_application_arn": "arn:aws:..." | null,
    "assignments": [
      {"principal_type": "GROUP", "principal_id": "...", "principal_display_name": "..."}
    ],
    "job_id": "abc123",
    "caller_arn": "arn:aws:iam::...:user/..."
  }

Output:
  {
    "role_name": "AAM-AdminAccess",
    "role_arn": "arn:aws:iam::123456789012:role/aam/AAM-AdminAccess",
    "account_id": "123456789012",
    "permission_set": "AdminAccess",
    "status": "created" | "already exists" | "error",
    "entitlements": [{"principal_id": "...", "status": "created" | "error"}]
  }
"""

import json
import os
import sys
from datetime import datetime, timezone

import boto3

from shared.credentials import assume_role

EXTERNAL_ID = os.environ.get("EXTERNAL_ID", "")

AAM_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "AAMTrustPolicyStatement",
        "Effect": "Allow",
        "Principal": {"Service": "account-access-preview.amazonaws.com"},
        "Action": ["sts:AssumeRole", "sts:SetContext"],
    }],
})


def lambda_handler(event, context):
    """Create one IAM role and optionally AAM entitlements."""
    ps = event["permission_set"]
    account_id = event["account_id"]
    role_path = event.get("role_path", "/aam/")
    role_name_template = event.get("role_name_template", "AAM-{name}")
    aam_application_arn = event.get("aam_application_arn")
    assignments = event.get("assignments", [])

    role_name = role_name_template.replace("{name}", ps["name"])

    # Assume into the target account
    session = assume_role(account_id, session_suffix="idc-apply")
    iam = session.client("iam")

    role_arn = f"arn:aws:iam::{account_id}:role{role_path}{role_name}"
    role_status = "created"

    try:
        # Idempotency check
        try:
            iam.get_role(RoleName=role_name)
            role_status = "already exists"
        except iam.exceptions.NoSuchEntityException:
            # Create the role
            iam.create_role(
                RoleName=role_name,
                Path=role_path,
                AssumeRolePolicyDocument=AAM_TRUST_POLICY,
                Description=f"Created by Truffle for permission set {ps['name']}",
                Tags=[
                    {"Key": "ManagedBy", "Value": "Truffle-IdC-Migration"},
                    {"Key": "SourcePermissionSet", "Value": ps["name"]},
                ],
            )

            # Attach AWS managed policies
            for p in ps.get("aws_managed_policies", []):
                try:
                    iam.attach_role_policy(RoleName=role_name, PolicyArn=p["arn"])
                except Exception:
                    pass

            # Attach customer managed policy references
            for ref in ps.get("customer_managed_policy_references", []):
                path_prefix = ref.get("path", "/")
                cmp_arn = f"arn:aws:iam::{account_id}:policy{path_prefix}{ref['name']}"
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

    except Exception as e:
        return {
            "role_name": role_name,
            "role_arn": role_arn,
            "account_id": account_id,
            "permission_set": ps["name"],
            "status": "error",
            "error": str(e),
            "entitlements": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Create AAM entitlements if application ARN provided
    entitlement_results = []
    if aam_application_arn and assignments:
        # AAM client needs to be called from the hub account (where the app is registered)
        # For now, use the same session — this may need adjustment depending on where
        # the AAM application lives.
        hub_account_id = event.get("hub_account_id", account_id)
        if hub_account_id != account_id:
            hub_session = assume_role(hub_account_id, session_suffix="idc-apply-aam")
        else:
            hub_session = session

        aam_region = event.get("aam_region", "us-east-1")
        try:
            aam_client = hub_session.client(
                "accountaccess",
                region_name=aam_region,
                endpoint_url=f"https://account-access-preview.{aam_region}.api.aws",
            )

            for assignment in assignments:
                principal_type = assignment.get("principal_type", "GROUP")
                principal_id = assignment.get("principal_id", "")

                principal_block = {}
                if principal_type == "USER":
                    principal_block["userId"] = principal_id
                else:
                    principal_block["groupId"] = principal_id

                try:
                    aam_client.create_entitlement(
                        applicationArn=aam_application_arn,
                        entitlement={
                            "principalRole": {
                                "principal": {"identityCenter": principal_block},
                                "roleArn": role_arn,
                            }
                        },
                    )
                    entitlement_results.append({
                        "principal_id": principal_id,
                        "principal_type": principal_type,
                        "status": "created",
                    })
                except Exception as e:
                    error_str = str(e)
                    status = "already exists" if "Conflict" in error_str or "AlreadyExists" in error_str else "error"
                    entitlement_results.append({
                        "principal_id": principal_id,
                        "principal_type": principal_type,
                        "status": status,
                        "error": error_str if status == "error" else None,
                    })
        except Exception as e:
            entitlement_results.append({
                "principal_id": "",
                "status": "error",
                "error": f"AAM client error: {str(e)}",
            })

    return {
        "role_name": role_name,
        "role_arn": role_arn,
        "account_id": account_id,
        "permission_set": ps["name"],
        "status": role_status,
        "entitlements": entitlement_results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
