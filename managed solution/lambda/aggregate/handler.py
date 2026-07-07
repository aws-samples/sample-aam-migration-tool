"""
Aggregate Lambda — merges results from all parallel scan/discover units,
writes the final payload to S3, and marks the DynamoDB job as complete.

Input (from Step Functions):
  {
    "job_id": "abc123",
    "caller_arn": "arn:aws:iam::...:user/...",
    "job_type": "policy-scan" | "iam-discover" | "iam-migrate",
    "results": [
      { per-unit output from scan-unit/scan-global/discover-roles/migrate-role }
    ],
    "params": { original job parameters }
  }

Output:
  {
    "job_id": "abc123",
    "status": "done",
    "result_key": "callers/<hash>/policy-scan/abc123.json",
    "summary": { ... }
  }
"""

import hashlib
import json
import os
import sys

import boto3

from shared.dynamodb_helpers import mark_complete, mark_error

RESULTS_BUCKET = os.environ.get("RESULTS_BUCKET", "")
JOBS_TABLE = os.environ.get("JOBS_TABLE", "TruffleJobs")

s3_client = boto3.client("s3")


def lambda_handler(event, context):
    """Aggregate results and finalize the job."""
    job_id = event["job_id"]
    caller_arn = event["caller_arn"]
    job_type = event["job_type"]
    unit_results = event.get("results", [])
    params = event.get("params", {})

    try:
        if job_type == "policy-scan":
            payload = _aggregate_policy_scan(unit_results, params)
        elif job_type == "iam-discover":
            payload = _aggregate_iam_discover(unit_results, params)
        elif job_type == "iam-migrate":
            payload = _aggregate_iam_migrate(unit_results, params)
        elif job_type == "idc-discover":
            payload = _aggregate_idc_discover(unit_results, params)
        else:
            payload = {"results": unit_results}

        # Write to S3
        caller_hash = hashlib.sha256(caller_arn.encode()).hexdigest()[:16]
        result_key = f"callers/{caller_hash}/{job_type}/{job_id}.json"

        s3_client.put_object(
            Bucket=RESULTS_BUCKET,
            Key=result_key,
            Body=json.dumps(payload, default=str),
            ContentType="application/json",
        )

        # Mark job complete
        mark_complete(caller_arn, job_id, result_key)

        return {
            "job_id": job_id,
            "status": "done",
            "result_key": result_key,
            "summary": payload.get("summary", {}),
        }

    except Exception as e:
        mark_error(caller_arn, job_id, str(e))
        return {
            "job_id": job_id,
            "status": "error",
            "error": str(e),
        }


def _aggregate_policy_scan(unit_results: list, params: dict) -> dict:
    """Merge policy scan results from all account+region units."""
    all_matches = []
    resources_scanned = 0
    errors = []

    for unit in unit_results:
        if isinstance(unit, dict):
            all_matches.extend(unit.get("matches", []))
            resources_scanned += unit.get("resources_scanned", 0)
            if unit.get("error"):
                errors.append(unit["error"])

    # Collect unique regions and accounts
    regions = sorted({m.get("region", "") for m in all_matches if m.get("region")})
    accounts = sorted({m.get("account_id", "") for m in all_matches if m.get("account_id")})

    return {
        "search_terms": params.get("search_terms", []),
        "total_matches": len(all_matches),
        "resources_scanned": resources_scanned,
        "regions_scanned": regions,
        "accounts_scanned": accounts,
        "matches": all_matches,
        "errors": errors,
        "summary": {
            "total_matches": len(all_matches),
            "resources_scanned": resources_scanned,
            "regions_count": len(regions),
            "accounts_count": len(accounts),
            "errors_count": len(errors),
        },
    }


def _aggregate_iam_discover(unit_results: list, params: dict) -> dict:
    """Merge IAM role discovery results from all accounts."""
    all_roles = []
    roles_scanned = 0

    for unit in unit_results:
        if isinstance(unit, dict):
            all_roles.extend(unit.get("roles", []))
            roles_scanned += unit.get("roles_scanned", 0)

    return {
        "idp_arn": params.get("idp_arn", ""),
        "total_roles": len(all_roles),
        "roles_scanned": roles_scanned,
        "roles": all_roles,
        "accounts_scanned": len(unit_results),
        "summary": {
            "total_roles": len(all_roles),
            "roles_scanned": roles_scanned,
            "accounts_scanned": len(unit_results),
        },
    }


def _aggregate_iam_migrate(unit_results: list, params: dict) -> dict:
    """Merge migration results from all role updates."""
    results = [r for r in unit_results if isinstance(r, dict)]

    return {
        "mode": params.get("mode", "ADD"),
        "total": len(results),
        "results": results,
        "summary": {
            "total": len(results),
            "success": len([r for r in results if r.get("status") == "success"]),
            "skipped": len([r for r in results if r.get("status") == "skipped"]),
            "error": len([r for r in results if r.get("status") == "error"]),
        },
    }


def _aggregate_idc_discover(unit_results: list, params: dict) -> dict:
    """Merge IdC discovery results."""
    # IdC discovery typically runs as a single unit (the hub account),
    # so this is mostly a passthrough with standard wrapping.
    if unit_results and isinstance(unit_results[0], dict):
        return {
            **unit_results[0],
            "summary": {
                "permission_sets": unit_results[0].get("total_permission_sets", 0),
                "assignments": unit_results[0].get("total_assignments", 0),
            },
        }
    return {"results": unit_results, "summary": {}}
