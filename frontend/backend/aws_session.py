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
