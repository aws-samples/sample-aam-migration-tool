"""
DynamoDB helper functions for job state management.
"""

import os
import time
from datetime import datetime, timezone

import boto3

JOBS_TABLE = os.environ.get("JOBS_TABLE", "TruffleJobs")

dynamodb = boto3.resource("dynamodb")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ttl_30_days() -> int:
    return int(time.time()) + (30 * 24 * 3600)


def create_job(caller_arn: str, job_id: str, job_type: str, params: dict) -> dict:
    """Write a new job record to DynamoDB."""
    table = dynamodb.Table(JOBS_TABLE)
    item = {
        "PK": f"CALLER#{caller_arn}",
        "SK": f"JOB#{job_id}",
        "job_id": job_id,
        "type": job_type,
        "status": "running",
        "progress": {
            "completed_units": 0,
            "total_units": 0,
            "message": "starting",
        },
        "params": params,
        "started_at": _now_iso(),
        "finished_at": None,
        "result_key": None,
        "error": None,
        "TTL": _ttl_30_days(),
    }
    table.put_item(Item=item)
    return item


def update_progress(caller_arn: str, job_id: str, progress: dict):
    """Update the progress map on a running job."""
    table = dynamodb.Table(JOBS_TABLE)
    table.update_item(
        Key={"PK": f"CALLER#{caller_arn}", "SK": f"JOB#{job_id}"},
        UpdateExpression="SET progress = :p",
        ExpressionAttributeValues={":p": progress},
    )


def mark_complete(caller_arn: str, job_id: str, result_key: str):
    """Mark a job as done and record the S3 result key."""
    table = dynamodb.Table(JOBS_TABLE)
    table.update_item(
        Key={"PK": f"CALLER#{caller_arn}", "SK": f"JOB#{job_id}"},
        UpdateExpression="SET #s = :s, finished_at = :f, result_key = :r",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "done",
            ":f": _now_iso(),
            ":r": result_key,
        },
    )


def mark_error(caller_arn: str, job_id: str, error_msg: str):
    """Mark a job as failed."""
    table = dynamodb.Table(JOBS_TABLE)
    table.update_item(
        Key={"PK": f"CALLER#{caller_arn}", "SK": f"JOB#{job_id}"},
        UpdateExpression="SET #s = :s, finished_at = :f, #e = :e",
        ExpressionAttributeNames={"#s": "status", "#e": "error"},
        ExpressionAttributeValues={
            ":s": "error",
            ":f": _now_iso(),
            ":e": error_msg,
        },
    )


def get_job(caller_arn: str, job_id: str) -> dict | None:
    """Fetch a job record, or None if not found."""
    table = dynamodb.Table(JOBS_TABLE)
    resp = table.get_item(
        Key={"PK": f"CALLER#{caller_arn}", "SK": f"JOB#{job_id}"}
    )
    return resp.get("Item")
