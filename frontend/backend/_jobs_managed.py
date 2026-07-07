"""
Managed backend job client — submits jobs to the Truffle managed API via
SigV4-signed requests and polls for status/results.

This module is the "managed" counterpart to _jobs_local.py. It implements the
same interface (start_scan, get, start_iam_discover, etc.) but delegates all
work to the remote API Gateway + Step Functions backend.
"""

import json
from typing import Optional

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import requests

from . import config


def _get_session() -> boto3.Session:
    """Build a boto3 session for SigV4 signing."""
    if config.API_PROFILE:
        return boto3.Session(profile_name=config.API_PROFILE)
    return boto3.Session()


def _signed_request(method: str, path: str, body: Optional[dict] = None) -> dict:
    """
    Sign an HTTP request with SigV4 and send it to the managed API.

    Args:
        method: HTTP method (GET, POST).
        path: API path (e.g. /api/policy-analysis/scan).
        body: JSON body for POST requests.

    Returns:
        Parsed JSON response dict.

    Raises:
        RuntimeError: If the API returns a non-2xx status.
    """
    url = f"{config.API_ENDPOINT.rstrip('/')}{path}"
    data = json.dumps(body) if body else None

    headers = {"Content-Type": "application/json"} if body else {}

    # Create and sign the request
    session = _get_session()
    credentials = session.get_credentials().get_frozen_credentials()
    aws_request = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(credentials, "execute-api", config.API_REGION).add_auth(aws_request)

    # Send via requests
    response = requests.request(
        method=method,
        url=url,
        headers=dict(aws_request.headers),
        data=data,
        timeout=30,
    )

    if response.status_code >= 400:
        error_body = response.text
        raise RuntimeError(
            f"Managed API returned {response.status_code}: {error_body}"
        )

    return response.json()


# ─── Policy Analysis ─────────────────────────────────────────────────────────

def start_scan(params: dict) -> str:
    """Submit a policy scan job to the managed backend. Returns job_id."""
    resp = _signed_request("POST", "/api/policy-analysis/scan", body=params)
    return resp["job_id"]


# ─── IAM Federation Discovery ────────────────────────────────────────────────

def start_iam_discover(params: dict) -> str:
    """Submit an IAM federation discovery job. Returns job_id."""
    resp = _signed_request("POST", "/api/iam-federation/discover", body=params)
    return resp["job_id"]


# ─── IAM Federation Migration ────────────────────────────────────────────────

def start_iam_migrate(params: dict) -> str:
    """Submit an IAM trust policy migration job. Returns job_id."""
    resp = _signed_request("POST", "/api/iam-federation/migrate", body=params)
    return resp["job_id"]


# ─── IdC Discovery ───────────────────────────────────────────────────────────

def start_idc_discover(params: dict) -> str:
    """Submit an IdC discovery job. Returns job_id."""
    resp = _signed_request("POST", "/api/idc/discover", body=params)
    return resp["job_id"]


# ─── IdC Apply (reuses migrate workflow) ─────────────────────────────────────

def start_idc_apply(params: dict) -> str:
    """Submit an IdC apply job. Returns job_id."""
    # IdC apply reuses the discover endpoint with apply params
    resp = _signed_request("POST", "/api/idc/discover", body={**params, "apply": True})
    return resp["job_id"]


# ─── Shared: Get job status ──────────────────────────────────────────────────

def get(job_id: str) -> Optional[dict]:
    """
    Get the current status of a job from the managed backend.

    Returns a dict matching the shape of _jobs_local.get():
      {
        "id": "...",
        "type": "policy-scan",
        "status": "running" | "done" | "error",
        "progress": { "completed_units": ..., "total_units": ..., "message": ... },
        "started_at": "...",
        "finished_at": "...",
        "error": "..." | None,
        "result": { ... } | None  (populated when status == "done")
      }
    """
    try:
        status_resp = _signed_request("GET", f"/api/policy-analysis/status?job={job_id}")
    except RuntimeError:
        return None

    # If job is done, fetch the full result
    result = None
    if status_resp.get("status") == "done":
        try:
            result_resp = _signed_request("GET", f"/api/policy-analysis/result?job={job_id}")
            result = result_resp.get("data")
        except RuntimeError:
            pass

    return {
        "id": status_resp.get("id", job_id),
        "type": status_resp.get("type", "unknown"),
        "status": status_resp.get("status", "unknown"),
        "progress": status_resp.get("progress", {}),
        "started_at": status_resp.get("started_at"),
        "finished_at": status_resp.get("finished_at"),
        "error": status_resp.get("error"),
        "result": result,
    }
