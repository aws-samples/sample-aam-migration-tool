"""
Cross-account credential resolution for Truffle Lambda functions.

Assumes the TruffleRole in target accounts using the external ID
configured at deployment time.
"""

import os

import boto3

EXTERNAL_ID = os.environ.get("EXTERNAL_ID", "")
ROLE_NAME = "TruffleRole"


def assume_role(account_id: str, session_suffix: str = "scan") -> boto3.Session:
    """
    Assume TruffleRole in the given account and return a boto3 Session.

    Args:
        account_id: Target AWS account ID.
        session_suffix: Appended to role session name for CloudTrail clarity.

    Returns:
        A boto3.Session with temporary credentials for the target account.
    """
    sts = boto3.client("sts")
    resp = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{ROLE_NAME}",
        RoleSessionName=f"truffle-{session_suffix}-{account_id}",
        ExternalId=EXTERNAL_ID,
        DurationSeconds=3600,
    )
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def get_caller_arn_from_event(event: dict) -> str:
    """
    Extract the caller's IAM ARN from the API Gateway request context.

    Used to namespace DynamoDB entries per caller.
    """
    request_context = event.get("requestContext", {})
    identity = request_context.get("identity", {})
    return identity.get("userArn", "unknown")
