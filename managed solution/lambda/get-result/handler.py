"""
Get Result Lambda — fetches the completed job result from S3.

Invoked by GET to:
  /api/policy-analysis/result?job=<job_id>
  /api/iam-federation/discover/result?job=<job_id>
  /api/idc/discover/result?job=<job_id>
"""

import json
import os
import sys

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from credentials import get_caller_arn_from_event
from dynamodb_helpers import get_job

RESULTS_BUCKET = os.environ.get("RESULTS_BUCKET", "")
s3_client = boto3.client("s3")


def lambda_handler(event, context):
    """Handle GET requests for job results."""
    caller_arn = get_caller_arn_from_event(event)
    params = event.get("queryStringParameters") or {}
    job_id = params.get("job")

    if not job_id:
        return _response(400, {"error": "Missing 'job' query parameter"})

    job = get_job(caller_arn, job_id)
    if not job:
        return _response(404, {"error": f"Job {job_id} not found"})

    if job["status"] != "done":
        return _response(409, {
            "error": f"Job is not complete (status: {job['status']})",
            "status": job["status"],
        })

    result_key = job.get("result_key")
    if not result_key:
        return _response(404, {"error": "No result available for this job"})

    # Read result from S3
    try:
        resp = s3_client.get_object(Bucket=RESULTS_BUCKET, Key=result_key)
        body = resp["Body"].read().decode("utf-8")
        result_data = json.loads(body)
    except Exception as e:
        return _response(500, {"error": f"Failed to read result: {str(e)}"})

    return _response(200, {
        "job_id": job_id,
        "type": job["type"],
        "finished_at": job.get("finished_at"),
        "data": result_data,
    })


def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body, default=str),
    }
