"""Shared pytest fixtures and Hypothesis configuration for IdC-to-AAM tests."""

from __future__ import annotations

import os
import sys

import pytest
from hypothesis import HealthCheck, settings

# Make the package modules importable when running pytest from the
# "Identity Center to AAM" directory. Both the package root (for the
# implementation modules) and the tests directory (for `strategies`) are
# placed on sys.path.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


# ─── Hypothesis profile ───────────────────────────────────────────────────────

settings.register_profile(
    "dev",
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
settings.load_profile("dev")


# ─── Common fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def region_name() -> str:
    return "us-east-1"


@pytest.fixture(autouse=True)
def _aws_credentials(monkeypatch):
    """Mocked AWS credentials so moto-backed clients never hit a real account."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
