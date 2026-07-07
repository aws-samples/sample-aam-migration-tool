"""
Start Job Lambda — creates a DynamoDB job record and starts the appropriate
Step Functions state machine execution.

Invoked by POST to:
  /api/policy-analysis/scan
  /api/iam-federation/discover
  /api/iam-federation/migrate
  /api/idc/discover
"""

import json
import os
import uuid

import boto3

# Add shared layer to path
import sys
import os

from shared.credentials import get_caller_arn_from_event
from shared.dynamodb_helpers import create_job

POLICY_SCAN_SM_ARN = os.environ.get("POLICY_SCAN_SM_ARN", "")
IAM_DISCOVER_SM_ARN = os.environ.get("IAM_DISCOVER_SM_ARN", "")
IAM_MIGRATE_SM_ARN = os.environ.get("IAM_MIGRATE_SM_ARN", "")
IDC_DISCOVER_SM_ARN = os.environ.get("IDC_DISCOVER_SM_ARN", "")
IDC_APPLY_SM_ARN = os.environ.get("IDC_APPLY_SM_ARN", "")

sfn_client = boto3.client("stepfunctions")

# Map API path to job type and state machine ARN
ROUTE_MAP = {
    "/api/policy-analysis/scan": ("policy-scan", POLICY_SCAN_SM_ARN),
    "/api/iam-federation/discover": ("iam-discover", IAM_DISCOVER_SM_ARN),
    "/api/iam-federation/migrate": ("iam-migrate", IAM_MIGRATE_SM_ARN),
    "/api/idc/discover": ("idc-discover", IDC_DISCOVER_SM_ARN),
    "/api/idc/apply": ("idc-apply", IDC_APPLY_SM_ARN),
}


def lambda_handler(event, context):
    """Handle POST requests to start a new job."""
    caller_arn = get_caller_arn_from_event(event)

    # REST API: "resource" is the route template, "path" includes the stage.
    # Try resource first (exact match), then fall back to path with stage stripped.
    path = event.get("resource", "")
    if not path or path not in ROUTE_MAP:
        # Try the raw path with stage prefix stripped
        raw_path = event.get("path", "")
        # Strip stage prefix like /prod/api/... -> /api/...
        if "/api/" in raw_path:
            path = "/api/" + raw_path.split("/api/", 1)[1]
        else:
            path = raw_path

    body = json.loads(event.get("body", "{}") or "{}")

    # Determine job type from the route
    job_type, sm_arn = ROUTE_MAP.get(path, (None, None))
    if not job_type or not sm_arn:
        return _response(400, {"error": f"Unknown route: {path}"})

    # Generate job ID
    job_id = uuid.uuid4().hex[:12]

    # Create DynamoDB record
    create_job(caller_arn, job_id, job_type, body)

    # Start Step Functions execution
    # Normalize field names: the UI sends "target_account_ids" but the ASL
    # expects "account_ids" for the Map state ItemsPath.
    sf_input = {
        "job_id": job_id,
        "caller_arn": caller_arn,
        "job_type": job_type,
        **body,
    }

    # ── Normalize and fill defaults per job type ────────────────────────────
    # Every field referenced by a JSONPath in the ASL must exist in the input,
    # otherwise Step Functions fails with States.ReferencePathConflict.

    # Common: account_ids (from target_account_ids or empty)
    if "account_ids" not in sf_input and "target_account_ids" in sf_input:
        sf_input["account_ids"] = sf_input["target_account_ids"]
    if "account_ids" not in sf_input:
        sf_input["account_ids"] = []

    if job_type == "policy-scan":
        sf_input.setdefault("search_terms", [])
        sf_input.setdefault("services", None)
        sf_input.setdefault("management_account", False)
        sf_input.setdefault("regions", [])

    elif job_type == "iam-discover":
        sf_input.setdefault("idp_arn", "")

    elif job_type == "iam-migrate":
        sf_input.setdefault("role_arns", [])
        sf_input.setdefault("mode", "ADD")
        sf_input.setdefault("idp_arn", "")

    elif job_type == "idc-discover":
        sf_input.setdefault("region", "us-east-1")
        sf_input.setdefault("account_scope", "single")
        if "hub_account_id" not in sf_input:
            accounts = sf_input.get("account_ids") or []
            sf_input["hub_account_id"] = accounts[0] if accounts else ""

    elif job_type == "idc-apply":
        sf_input.setdefault("pairs", [])
        sf_input.setdefault("role_path", "/aam/")
        sf_input.setdefault("role_name_template", "AAM-{name}")
        sf_input.setdefault("aam_application_arn", "")
        sf_input.setdefault("aam_region", "us-east-1")
        if "hub_account_id" not in sf_input:
            accounts = sf_input.get("account_ids") or []
            sf_input["hub_account_id"] = accounts[0] if accounts else ""

        # Build the "pairs" array from UI inputs if not already provided.
        # The UI sends selected_permission_sets (ARNs) and selected_assignments
        # (flat list). We need to group them into {permission_set, account_id, assignments}.
        # The permission set detail comes from the most recent discovery result in S3.
        if not sf_input["pairs"] and sf_input.get("selected_permission_sets"):
            sf_input["pairs"] = _build_apply_pairs(sf_input, caller_arn)

    sfn_client.start_execution(
        stateMachineArn=sm_arn,
        name=f"{job_type}-{job_id}",
        input=json.dumps(sf_input, default=str),
    )

    return _response(200, {"job_id": job_id, "status": "running"})


def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }


def _build_apply_pairs(sf_input: dict, caller_arn: str) -> list[dict]:
    """
    Build the structured 'pairs' array for the idc-apply state machine.

    Reads the most recent idc-discover result from S3 to get permission set
    details, then groups assignments by (permission_set_arn, account_id).

    Each pair: {permission_set: {...}, account_id: "...", assignments: [...]}
    """
    import hashlib
    s3_client = boto3.client("s3")
    results_bucket = os.environ.get("RESULTS_BUCKET", "")

    selected_ps_arns = set(sf_input.get("selected_permission_sets", []))
    selected_assignments = sf_input.get("selected_assignments", [])

    # Try to find the most recent idc-discover result for this caller
    caller_hash = hashlib.sha256(caller_arn.encode()).hexdigest()[:16]
    prefix = f"callers/{caller_hash}/idc-discover/"

    discovery_data = None
    if results_bucket:
        try:
            resp = s3_client.list_objects_v2(Bucket=results_bucket, Prefix=prefix)
            objects = sorted(resp.get("Contents", []), key=lambda o: o["LastModified"], reverse=True)
            if objects:
                obj = s3_client.get_object(Bucket=results_bucket, Key=objects[0]["Key"])
                discovery_data = json.loads(obj["Body"].read().decode("utf-8"))
        except Exception:
            pass

    # Build permission set lookup from discovery data
    ps_lookup = {}
    if discovery_data:
        for ps in discovery_data.get("permission_sets", []):
            if ps.get("arn") in selected_ps_arns:
                ps_lookup[ps["arn"]] = {
                    "arn": ps["arn"],
                    "name": ps["name"],
                    "aws_managed_policies": ps.get("aws_managed_policies", []),
                    "customer_managed_policy_references": ps.get("customer_managed_policy_references", []),
                    "inline_policy": ps.get("inline_policy"),
                }

    # Group assignments by (permission_set_arn, account_id)
    from collections import defaultdict
    groups = defaultdict(list)
    for a in selected_assignments:
        key = (a.get("permission_set_arn", ""), a.get("account_id", ""))
        groups[key].append({
            "principal_type": a.get("principal_type", "GROUP"),
            "principal_id": a.get("principal_id", ""),
            "principal_display_name": a.get("principal_display_name", ""),
        })

    # Build pairs
    pairs = []
    for (ps_arn, account_id), assignments in groups.items():
        if ps_arn not in selected_ps_arns:
            continue
        ps_detail = ps_lookup.get(ps_arn, {"arn": ps_arn, "name": ps_arn.rsplit("/", 1)[-1],
                                            "aws_managed_policies": [], "customer_managed_policy_references": [],
                                            "inline_policy": None})
        pairs.append({
            "permission_set": ps_detail,
            "account_id": account_id,
            "assignments": assignments,
        })

    return pairs
