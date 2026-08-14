"""Hub-and-spoke session helpers and shared botocore configuration.

Mirrors the conventions of `truffle/Utilites/resource_policy_scan/scan_resource_policies.py`:
the tool runs from a hub account using default credentials and assumes a role
in each spoke (target) account for IAM mutations.
"""

from __future__ import annotations

from dataclasses import dataclass

import boto3
import botocore.config


@dataclass(frozen=True)
class HubContext:
    session: boto3.Session
    account_id: str
    caller_arn: str
    region: str


def boto_config(workers: int) -> botocore.config.Config:
    """Standard retry config used across all clients (Req 15.4).

    Adaptive retry mode handles throttling with exponential backoff;
    max_attempts=5 satisfies "up to 5 retry attempts" from Requirement 15.4.
    """
    return botocore.config.Config(
        retries={"mode": "adaptive", "max_attempts": 5},
        max_pool_connections=max(10, workers * 2),
    )


def get_hub_context(region: str = "us-east-1") -> HubContext:
    """Resolve the hub session via STS GetCallerIdentity (Req 1.7)."""
    session = boto3.Session(region_name=region)
    sts = session.client("sts", config=boto_config(workers=5))
    identity = sts.get_caller_identity()
    return HubContext(
        session=session,
        account_id=identity["Account"],
        caller_arn=identity["Arn"],
        region=region,
    )


def assume_spoke_session(
    account_id: str,
    role_name: str,
    run_id: str,
    *,
    region: str = "us-east-1",
    workers: int = 5,
) -> boto3.Session:
    """Assume role in the target account and return a new boto3.Session.

    Raises botocore.exceptions.ClientError on failure. Callers are responsible
    for logging-and-skipping per Requirement 1.5.
    """
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    sts = boto3.client("sts", region_name=region, config=boto_config(workers))
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"idc-to-aam-{run_id[:32]}",
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
