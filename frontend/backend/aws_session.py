"""
AWS credential / session helpers.

The console MUST leverage the local AWS credential chain and let the user pick
which named profiles to use. These helpers enumerate available profiles and
build boto3 sessions from them.
"""

from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def list_profiles() -> list[str]:
    """Return the named profiles available in the local AWS config."""
    try:
        return sorted(boto3.Session().available_profiles)
    except (BotoCoreError, ClientError):
        return []


def build_session(profile: Optional[str] = None) -> boto3.Session:
    """Build a boto3 session for the given profile (or the default chain)."""
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def build_assumed_session(
    account_id: str,
    role_name: str,
    base_profile: Optional[str] = None,
    region: Optional[str] = None,
    external_id: Optional[str] = None,
) -> boto3.Session:
    """
    Build a boto3 session by assuming ``role_name`` in ``account_id``.

    This is the "assume role" authentication path: rather than relying on a
    distinct named profile per account, the caller supplies a list of account
    IDs and a single role name to assume in each. The AssumeRole call itself is
    made with ``base_profile`` (or the default credential chain when omitted),
    and the returned session carries the resulting temporary credentials.

    Read-only here only in that it returns a session; the scan that uses it
    performs read/describe/list calls. Raises on AssumeRole failure so the
    caller can report the account as un-scannable.
    """
    base = build_session(base_profile)
    sts = base.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    kwargs = {"RoleArn": role_arn, "RoleSessionName": "truffle-policy-scan"}
    if external_id:
        kwargs["ExternalId"] = external_id
    creds = sts.assume_role(**kwargs)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def whoami(profile: Optional[str] = None) -> dict:
    """
    Resolve the caller identity for a profile.

    Returns a dict with ``account``, ``arn``, and ``user_id`` on success, or
    an ``error`` key describing why the lookup failed. Read-only (STS
    GetCallerIdentity) so it is safe to call freely.
    """
    try:
        session = build_session(profile)
        identity = session.client("sts").get_caller_identity()
        return {
            "profile": profile or "(default)",
            "account": identity["Account"],
            "arn": identity["Arn"],
            "user_id": identity["UserId"],
        }
    except (BotoCoreError, ClientError) as exc:
        return {"profile": profile or "(default)", "error": str(exc)}
