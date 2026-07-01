"""Tests for the config module."""

from __future__ import annotations

import os
import tempfile
import textwrap

import pytest

from config import ConfigError, parse_args, render_cmp_name, render_role_name, validate


def _trust_policy_path(tmp_path) -> str:
    p = tmp_path / "trust.json"
    p.write_text(
        textwrap.dedent(
            """
            {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sts.amazonaws.com"},"Action":"sts:AssumeRole"}]}
            """
        )
    )
    return str(p)


# ── Trust policy is required (both modes need it to define the roles) ─────────
def test_trust_policy_required():
    """A trust policy is always required outside out-of-scope runs.

    Validates: Requirement 5.5
    """
    cfg = parse_args([])
    with pytest.raises(ConfigError, match="trust-policy"):
        validate(cfg)


def test_trust_policy_present_passes_validation(tmp_path):
    tp = _trust_policy_path(tmp_path)
    cfg = parse_args([
        "--trust-policy", tp,
        "--aam-application-arn",
        "arn:aws:accountaccess:us-east-1:111111111111:application/app-test",
    ])
    validate(cfg)


def test_generate_iac_does_not_require_aam_arn(tmp_path):
    """generate-iac mode is the default and does not require an AAM application
    ARN (roles-only template is produced when it is absent)."""
    tp = _trust_policy_path(tmp_path)
    cfg = parse_args(["--trust-policy", tp])  # default mode = generate-iac
    validate(cfg)  # must not raise


# ── Property 25: Out-of-scope request short-circuits ──────────────────────────
def test_property_25_out_of_scope_short_circuits():
    """Property 25: Out-of-scope request short-circuits.

    Validates: Requirement 16.5
    """
    cfg = parse_args(["--scan-resource-policies"])
    assert cfg.out_of_scope_request is not None
    assert "resource_policy_scan" in cfg.out_of_scope_request


def test_iam_federation_out_of_scope():
    cfg = parse_args(["--migrate-iam-federation"])
    assert cfg.out_of_scope_request is not None
    assert "IAM Federation" in cfg.out_of_scope_request


def test_scp_out_of_scope():
    cfg = parse_args(["--analyze-scps"])
    assert cfg.out_of_scope_request is not None


# ── Other validation rules (these checks precede the trust-policy check) ──────
def test_workers_must_be_positive():
    cfg = parse_args(["--workers", "0"])
    with pytest.raises(ConfigError, match="workers"):
        validate(cfg)


def test_role_name_template_must_contain_placeholder():
    cfg = parse_args(["--role-name-template", "no-placeholder"])
    with pytest.raises(ConfigError, match="permission_set_name"):
        validate(cfg)


def test_role_path_must_match_iam_format():
    cfg = parse_args(["--role-path", "no-leading-slash"])
    with pytest.raises(ConfigError, match="role-path"):
        validate(cfg)


def test_audit_to_cloudwatch_requires_log_group(tmp_path):
    tp = _trust_policy_path(tmp_path)
    cfg = parse_args(["--trust-policy", tp, "--audit-to-cloudwatch"])
    with pytest.raises(ConfigError, match="cloudwatch-log-group"):
        validate(cfg)


def test_audit_to_file_requires_path(tmp_path):
    tp = _trust_policy_path(tmp_path)
    cfg = parse_args(["--trust-policy", tp, "--audit-to-file"])
    with pytest.raises(ConfigError, match="audit-file-path"):
        validate(cfg)


def test_account_scope_defaults_to_single():
    cfg = parse_args([])
    assert cfg.account_scope == "single"


def test_property_19_generate_iac_is_default_mode():
    """Property 19: generate-iac is the default role-creation mode.

    Validates: Requirement 7.3
    """
    cfg = parse_args([])
    assert cfg.role_creation_mode == "generate-iac"


def test_apply_mode_parsed():
    cfg = parse_args(["--role-creation-mode", "apply"])
    assert cfg.role_creation_mode == "apply"


def test_aam_application_arn_required_in_apply_mode(tmp_path):
    tp = _trust_policy_path(tmp_path)
    cfg = parse_args(["--trust-policy", tp, "--role-creation-mode", "apply"])
    # trust-policy exists; apply mode requires an AAM application arn.
    with pytest.raises(ConfigError, match="aam-application-arn"):
        validate(cfg)


def test_single_scope_does_not_require_role_name_or_accounts(tmp_path):
    # Single scope (the default) needs neither account IDs nor a role name.
    tp = _trust_policy_path(tmp_path)
    cfg = parse_args(["--trust-policy", tp])
    validate(cfg)  # must not raise


def test_multi_scope_requires_account_ids():
    cfg = parse_args(["--account-scope", "multi", "--role-name", "MyRole"])
    with pytest.raises(ConfigError, match="--account-ids"):
        validate(cfg)


def test_multi_scope_requires_role_name():
    cfg = parse_args(
        ["--account-scope", "multi", "--account-ids", "111111111111"]
    )
    with pytest.raises(ConfigError, match="--role-name"):
        validate(cfg)


def test_multi_scope_with_accounts_and_role_passes(tmp_path):
    tp = _trust_policy_path(tmp_path)
    cfg = parse_args(
        [
            "--trust-policy", tp,
            "--account-scope", "multi",
            "--account-ids", "111111111111,222222222222",
            "--role-name", "MyRole",
        ]
    )
    validate(cfg)  # must not raise
    assert cfg.account_scope == "multi"
    assert cfg.account_ids == ("111111111111", "222222222222")


def test_tags_parsed_correctly():
    cfg = parse_args([
        "--tag", "Owner=Platform",
        "--tag", "Team=Identity",
    ])
    assert cfg.role_tags == {"Owner": "Platform", "Team": "Identity"}


def test_tags_must_be_key_equals_value():
    with pytest.raises(ConfigError, match="Tag"):
        parse_args(["--tag", "no-equals"])


def test_run_id_is_uuid_hex():
    cfg = parse_args([])
    assert len(cfg.run_id) == 32
    int(cfg.run_id, 16)  # parses as hex


def test_render_role_name_and_cmp_name():
    assert render_role_name("AAM-{permission_set_name}", "Admin") == "AAM-Admin"
    assert render_cmp_name("CMP-{permission_set_name}-inline", "Admin") == "CMP-Admin-inline"
