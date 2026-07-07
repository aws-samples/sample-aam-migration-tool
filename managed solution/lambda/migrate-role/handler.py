"""
Migrate Role Lambda — updates the trust policy on a single IAM role to add
(or replace) the AAM trust statement.

Input (from Step Functions):
  {
    "role_arn": "arn:aws:iam::123456789012:role/MyRole",
    "mode": "ADD" | "REPLACE",
    "idp_arn": "arn:aws:iam::...:saml-provider/OldIDP",  (for REPLACE mode)
    "job_id": "abc123",
    "caller_arn": "arn:aws:iam::...:user/..."
  }

Output:
  {
    "role_arn": "...",
    "role_name": "MyRole",
    "status": "success" | "skipped" | "error",
    "mode": "ADD",
    "previous_trust_policy": {...}
  }
"""

import json
import os
import sys
from datetime import datetime, timezone

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from credentials import assume_role

MIGRATION_LOG_TABLE = os.environ.get("MIGRATION_LOG_TABLE", "TruffleMigrationLog")

AAM_TRUST_STATEMENT = {
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

dynamodb = boto3.resource("dynamodb")


def lambda_handler(event, context):
    """Migrate a single role's trust policy."""
    role_arn = event["role_arn"]
    mode = event.get("mode", "ADD").upper()
    idp_arn = event.get("idp_arn", "")
    caller_arn = event.get("caller_arn", "unknown")
    job_id = event.get("job_id", "unknown")

    # Parse account_id and role_name from ARN
    parts = role_arn.split(":")
    account_id = parts[4] if len(parts) >= 5 else ""
    role_name = role_arn.split("/")[-1]

    try:
        session = assume_role(account_id, session_suffix="migrate")
        iam = session.client("iam")

        # Get current trust policy
        role_resp = iam.get_role(RoleName=role_name)
        trust_doc = role_resp["Role"]["AssumeRolePolicyDocument"]

        # Check if already migrated
        existing_sids = {s.get("Sid") for s in trust_doc.get("Statement", [])}
        if AAM_TRUST_STATEMENT["Sid"] in existing_sids:
            result = _build_result(role_arn, role_name, "skipped", mode, trust_doc,
                                   reason="Already has AAM trust statement")
            _log_migration(caller_arn, role_arn, result)
            return result

        # Build new trust policy
        if mode == "ADD":
            new_doc = dict(trust_doc)
            new_doc["Statement"] = list(trust_doc["Statement"]) + [AAM_TRUST_STATEMENT]
        elif mode == "REPLACE":
            kept = []
            for stmt in trust_doc["Statement"]:
                federated = stmt.get("Principal", {}).get("Federated", "")
                if isinstance(federated, str):
                    federated = [federated]
                if idp_arn not in federated:
                    kept.append(stmt)
            kept.append(AAM_TRUST_STATEMENT)
            new_doc = dict(trust_doc)
            new_doc["Statement"] = kept
        else:
            result = _build_result(role_arn, role_name, "error", mode, trust_doc,
                                   error=f"Invalid mode: {mode}")
            _log_migration(caller_arn, role_arn, result)
            return result

        # Apply update
        iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(new_doc),
        )

        result = _build_result(role_arn, role_name, "success", mode, trust_doc)
        _log_migration(caller_arn, role_arn, result)
        return result

    except Exception as e:
        result = _build_result(role_arn, role_name, "error", mode, None, error=str(e))
        _log_migration(caller_arn, role_arn, result)
        return result


def _build_result(role_arn, role_name, status, mode, previous_trust_policy,
                  reason=None, error=None) -> dict:
    result = {
        "role_arn": role_arn,
        "role_name": role_name,
        "status": status,
        "mode": mode,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if previous_trust_policy:
        result["previous_trust_policy"] = previous_trust_policy
    if reason:
        result["reason"] = reason
    if error:
        result["error"] = error
    return result


def _log_migration(caller_arn: str, role_arn: str, result: dict):
    """Write a per-role migration entry to the migration log table."""
    try:
        table = dynamodb.Table(MIGRATION_LOG_TABLE)
        table.put_item(Item={
            "PK": f"CALLER#{caller_arn}",
            "SK": f"MIGRATE#{result['timestamp']}#{role_arn}",
            "role_arn": role_arn,
            "role_name": result["role_name"],
            "status": result["status"],
            "mode": result["mode"],
            "error": result.get("error"),
            "previous_trust_policy": result.get("previous_trust_policy"),
        })
    except Exception:
        pass  # Best-effort logging
