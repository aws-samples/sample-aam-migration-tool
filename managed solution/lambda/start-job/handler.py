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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from credentials import get_caller_arn_from_event
from dynamodb_helpers import create_job

POLICY_SCAN_SM_ARN = os.environ.get("POLICY_SCAN_SM_ARN", "")
IAM_DISCOVER_SM_ARN = os.environ.get("IAM_DISCOVER_SM_ARN", "")
IAM_MIGRATE_SM_ARN = os.environ.get("IAM_MIGRATE_SM_ARN", "")

sfn_client = boto3.client("stepfunctions")

# Map API path to job type and state machine ARN
ROUTE_MAP = {
    "/api/policy-analysis/scan": ("policy-scan", POLICY_SCAN_SM_ARN),
    "/api/iam-federation/discover": ("iam-discover", IAM_DISCOVER_SM_ARN),
    "/api/iam-federation/migrate": ("iam-migrate", IAM_MIGRATE_SM_ARN),
    "/api/idc/discover": ("idc-discover", IAM_DISCOVER_SM_ARN),  # reuses discover workflow
}


def lambda_handler(event, context):
    """Handle POST requests to start a new job."""
    caller_arn = get_caller_arn_from_event(event)
    path = event.get("resource", "") or event.get("path", "")
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
    sf_input = {
        "job_id": job_id,
        "caller_arn": caller_arn,
        "job_type": job_type,
        **body,
    }

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
