"""
Get Status Lambda — reads job progress from DynamoDB.

Invoked by GET to:
  /api/policy-analysis/status?job=<job_id>
  /api/iam-federation/discover/status?job=<job_id>
  /api/iam-federation/migrate/status?job=<job_id>
  /api/idc/discover/status?job=<job_id>
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from credentials import get_caller_arn_from_event
from dynamodb_helpers import get_job


def lambda_handler(event, context):
    """Handle GET requests for job status."""
    caller_arn = get_caller_arn_from_event(event)
    params = event.get("queryStringParameters") or {}
    job_id = params.get("job")

    if not job_id:
        return _response(400, {"error": "Missing 'job' query parameter"})

    job = get_job(caller_arn, job_id)
    if not job:
        return _response(404, {"error": f"Job {job_id} not found"})

    # Return status without the full params (they can be large)
    result = {
        "id": job["job_id"],
        "type": job["type"],
        "status": job["status"],
        "progress": job.get("progress", {}),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "error": job.get("error"),
    }

    return _response(200, result)


def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body, default=str),
    }
