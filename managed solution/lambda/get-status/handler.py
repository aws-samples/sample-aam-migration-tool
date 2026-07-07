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
from datetime import datetime, timezone

from shared.credentials import get_caller_arn_from_event
from shared.dynamodb_helpers import get_job, mark_error

# If a job has been "running" longer than this without completing, check SF status
STALE_JOB_THRESHOLD_SECONDS = 300  # 5 minutes


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

    # If the job is stuck "running", check if it's actually failed
    if job["status"] == "running" and job.get("started_at"):
        try:
            started = datetime.fromisoformat(job["started_at"])
            age_seconds = (datetime.now(timezone.utc) - started).total_seconds()
            if age_seconds > STALE_JOB_THRESHOLD_SECONDS:
                # Check Step Functions execution status
                import boto3
                sfn = boto3.client("stepfunctions")
                # List recent executions matching this job
                # The execution name is "{job_type}-{job_id}"
                job_type = job.get("type", "")
                exec_name = f"{job_type}-{job_id}"
                try:
                    sm_arns = _get_state_machine_arns()
                    for sm_arn in sm_arns:
                        try:
                            execs = sfn.list_executions(
                                stateMachineArn=sm_arn,
                                statusFilter="FAILED",
                                maxResults=20,
                            )
                            for ex in execs.get("executions", []):
                                if ex["name"] == exec_name:
                                    # SF failed — mark the job as error
                                    mark_error(caller_arn, job_id,
                                               "Step Functions execution failed. Check execution history for details.")
                                    job["status"] = "error"
                                    job["error"] = "Step Functions execution failed. Check execution history for details."
                                    break
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass

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


def _get_state_machine_arns() -> list[str]:
    """Get the state machine ARNs from environment (set by CDK)."""
    arns = []
    for key in ["POLICY_SCAN_SM_ARN", "IAM_DISCOVER_SM_ARN", "IAM_MIGRATE_SM_ARN"]:
        arn = os.environ.get(key, "")
        if arn:
            arns.append(arn)
    return arns


def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body, default=str),
    }
