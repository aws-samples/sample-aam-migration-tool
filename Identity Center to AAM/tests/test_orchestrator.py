"""Orchestrator tests: mode flow, confirmation, and out-of-scope short-circuit.

These tests exercise the wiring in idc_to_aam.main by monkeypatching the
phase collaborators so no real AWS calls are made.
"""

from __future__ import annotations

import builtins
import os

import pytest

import idc_to_aam
from aws_session import HubContext
from models import (
    AccountAssignmentRecord,
    ApplicationResult,
    Inventory,
    PermissionSetRecord,
)


# ─── Fixtures / fakes ─────────────────────────────────────────────────────────

def _inventory() -> Inventory:
    ps = PermissionSetRecord(
        arn="arn:aws:sso:::permissionSet/ssoins-x/ps-Admin",
        name="Admin",
        description="",
        session_duration="PT1H",
        inline_policy=None,
        aws_managed_policy_arns=("arn:aws:iam::aws:policy/AdministratorAccess",),
        customer_managed_policy_references=(),
        permission_boundary=None,
    )
    assignment = AccountAssignmentRecord(
        permission_set_arn=ps.arn,
        account_id="222222222222",
        principal_type="USER",
        principal_id="u1",
        principal_display_name="Omar",
    )
    return Inventory(
        hub_account_id="111111111111",
        idc_instance_arn="arn:aws:sso:::instance/ssoins-x",
        identity_store_id="d-1234567890",
        permission_sets=(ps,),
        assignments=(assignment,),
        run_id="rid-test",
        captured_at="2025-01-01T00:00:00+00:00",
    )


@pytest.fixture
def patched(monkeypatch, tmp_path):
    """Patch hub resolution and inventory so main() runs offline."""
    inv = _inventory()

    # A real trust policy file the validator and IaC generator can read.
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"account-access-preview.amazonaws.com"},'
        '"Action":["sts:AssumeRole","sts:SetContext"]}]}'
    )

    monkeypatch.setattr(
        idc_to_aam,
        "get_hub_context",
        lambda region="us-east-1": HubContext(
            session=None, account_id="111111111111",
            caller_arn="arn:aws:iam::111111111111:role/Caller", region=region,
        ),
    )
    monkeypatch.setattr(
        idc_to_aam.InventoryModule, "__init__",
        lambda self, hub, cfg, audit: setattr(self, "cfg", cfg) or None,
    )
    monkeypatch.setattr(
        idc_to_aam.InventoryModule, "run", lambda self: inv
    )

    # EntitlementCreator.run returns a benign supplied-application result.
    def _ent_run(self, inventory, role_results):
        app = ApplicationResult(
            application_arn=self.cfg.aam_application_arn,
            status="SUPPLIED" if self.cfg.role_creation_mode == "apply" else "SKIPPED",
            idc_instance_arn=inventory.idc_instance_arn,
        )
        return app, []

    monkeypatch.setattr(idc_to_aam.EntitlementCreator, "run", _ent_run)
    # Never construct a real AAM boto3 client.
    monkeypatch.setattr(idc_to_aam.EntitlementCreator, "__init__",
                        lambda self, hub, cfg, audit, aam_client=None: setattr(self, "cfg", cfg) or None)

    return type("Patched", (), {"tmp_path": tmp_path, "trust_path": str(trust_path)})()


# ─── Out-of-scope short-circuit (Req 19.5) ────────────────────────────────────

def test_out_of_scope_short_circuits(capsys):
    rc = idc_to_aam.main(["--scan-resource-policies"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "resource_policy_scan" in err


# ─── generate-iac runs without prompting and makes no AWS mutation ────────────

def test_generate_iac_runs_without_prompt(patched, monkeypatch):
    """generate-iac is the default safe path: it writes the template and never
    prompts (it changes nothing in AWS)."""
    # input() must never be called in generate-iac mode.
    monkeypatch.setattr(
        builtins, "input",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt")),
    )
    out_dir = str(patched.tmp_path / "iacout")
    rc = idc_to_aam.main(
        [
            "--role-creation-mode", "generate-iac",
            "--trust-policy", patched.trust_path,
            "--iac-output-dir", out_dir,
            "--plan-output", str(patched.tmp_path / "plan.xlsx"),
            "--mapping-output", str(patched.tmp_path / "map.json"),
            "--mapping-format", "JSON",
        ]
    )
    assert rc == 0
    # The template is written (no AWS mutation needed).
    assert os.path.isfile(os.path.join(out_dir, "rid-test", "roles.yaml"))


# ─── generate-iac full run writes roles.yaml ──────────────────────────────────

def test_generate_iac_run_writes_artifacts(patched):
    out_dir = str(patched.tmp_path / "iacout")
    rc = idc_to_aam.main(
        [
            "--role-creation-mode", "generate-iac",
            "--trust-policy", patched.trust_path,
            "--aam-application-arn", "arn:aws:accountaccess:us-east-1:111111111111:application/app-1",
            "--iac-output-dir", out_dir,
            "--plan-output", str(patched.tmp_path / "plan.xlsx"),
            "--mapping-output", str(patched.tmp_path / "map.json"),
            "--mapping-format", "JSON",
        ]
    )
    assert rc == 0
    run_dir = os.path.join(out_dir, "rid-test")
    assert os.path.isfile(os.path.join(run_dir, "roles.yaml"))


# ─── apply mode: declining the confirmation makes no change (Req 13) ──────────

def test_apply_decline_makes_no_change(patched, monkeypatch):
    # apply mode prompts once; answer 'no' to cancel.
    monkeypatch.setattr(builtins, "input", lambda *a, **k: "no")

    # role creation must never run if the user declines.
    def _boom(self, inventory):
        raise AssertionError("role creation must not run when confirmation declined")

    monkeypatch.setattr(idc_to_aam.RoleCreator, "run", _boom)

    rc = idc_to_aam.main(
        [
            "--role-creation-mode", "apply",
            "--trust-policy", patched.trust_path,
            "--aam-application-arn", "arn:aws:accountaccess:us-east-1:111111111111:application/app-1",
            "--plan-output", str(patched.tmp_path / "plan.xlsx"),
        ]
    )
    assert rc == 0


# ─── apply mode: --auto-approve skips the prompt ──────────────────────────────

def test_apply_auto_approve_skips_prompt(patched, monkeypatch):
    monkeypatch.setattr(
        builtins, "input",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt")),
    )
    ran = {"called": False}

    def _ran(self, inventory):
        ran["called"] = True
        return []

    monkeypatch.setattr(idc_to_aam.RoleCreator, "run", _ran)

    rc = idc_to_aam.main(
        [
            "--role-creation-mode", "apply",
            "--auto-approve",
            "--trust-policy", patched.trust_path,
            "--aam-application-arn", "arn:aws:accountaccess:us-east-1:111111111111:application/app-1",
            "--plan-output", str(patched.tmp_path / "plan.xlsx"),
            "--mapping-output", str(patched.tmp_path / "map.json"),
            "--mapping-format", "JSON",
        ]
    )
    assert rc == 0
    assert ran["called"] is True
