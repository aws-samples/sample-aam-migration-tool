"""Infrastructure-as-Code generator (generate-iac mode, Requirement 9).

Emits a single combined CloudFormation template (YAML) describing every IAM
role in the migration plan AND the AAM entitlements that map each IdC principal
to its role. Performs no AWS API calls.

Each role (``AWS::IAM::Role``):
  - name from the migration plan
  - the configured role path and tags
  - a trust policy granting the `account-access.amazonaws.com` service
    principal sts:AssumeRole + sts:SetContext (or an operator-supplied trust
    policy file when provided)
  - the AWS managed policies, inline policy, and customer managed policy
    references of the corresponding permission set (permissions identical to
    the permission set)
  - the configured permission boundary, if any

Each entitlement (``AWS::AccountAccess::Entitlement``):
  - the operator-supplied application ARN
  - the IdC principal (UserId or GroupId) from the assignment
  - the role ARN wired to the corresponding role resource via Fn::GetAtt

Terraform output is intentionally omitted: the Terraform provider for the AAM
preview service is not yet available, so only CloudFormation is generated.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from audit_logger import AuditLogger
from config import Config
from models import Inventory, PermissionSetRecord, RoleCreationResult


AAM_TRUST_SERVICE_PRINCIPAL = "account-access.amazonaws.com"
AAM_TRUST_ACTIONS = ["sts:AssumeRole", "sts:SetContext"]


class IaCGenerator:
    def __init__(self, cfg: Config, audit: AuditLogger) -> None:
        self.cfg = cfg
        self.audit = audit
        self._trust_policy_cache: dict | None = None

    # ── Trust policy ─────────────────────────────────────────────────────────

    def trust_policy_document(self) -> dict:
        """Return the AssumeRolePolicyDocument. When the operator supplies a
        trust policy file, use it; otherwise emit the canonical AAM trust policy
        (Req 9.3). Injects confused-deputy conditions (aws:SourceAccount,
        aws:SourceArn) when --aam-application-arn is provided."""
        if self._trust_policy_cache is not None:
            return self._trust_policy_cache

        if self.cfg.trust_policy_path and os.path.isfile(self.cfg.trust_policy_path):
            with open(self.cfg.trust_policy_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
        else:
            doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": AAM_TRUST_SERVICE_PRINCIPAL},
                        "Action": list(AAM_TRUST_ACTIONS),
                    }
                ],
            }

        # Inject confused-deputy conditions when AAM application ARN is available
        if self.cfg.aam_application_arn:
            app_arn = self.cfg.aam_application_arn
            # Extract source account from the application ARN (arn:aws:account-access:<region>:<account>:application/...)
            parts = app_arn.split(":")
            source_account = parts[4] if len(parts) >= 5 else ""
            for stmt in doc.get("Statement", []):
                principal = stmt.get("Principal", {})
                svc = principal.get("Service", "")
                if svc == AAM_TRUST_SERVICE_PRINCIPAL or svc == "account-access.amazonaws.com":
                    condition = stmt.setdefault("Condition", {})
                    str_eq = condition.setdefault("StringEquals", {})
                    if source_account:
                        str_eq["aws:SourceAccount"] = source_account
                    str_eq["aws:SourceArn"] = app_arn

        self._trust_policy_cache = doc
        return doc

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _tags_list(self) -> list[dict[str, str]]:
        return [{"Key": k, "Value": v} for k, v in sorted(self.cfg.role_tags.items())]

    # ── CloudFormation: roles ────────────────────────────────────────────────

    def role_to_cfn(self, ps: PermissionSetRecord, role_name: str) -> dict[str, Any]:
        """Build one AWS::IAM::Role CloudFormation resource (Req 9.2-9.6)."""
        props: dict[str, Any] = {
            "RoleName": role_name,
            "Path": self.cfg.role_path,
            "AssumeRolePolicyDocument": self.trust_policy_document(),
        }

        managed = list(ps.aws_managed_policy_arns)
        # CMP references resolved to ARNs in the deploying account.
        for ref in ps.customer_managed_policy_references:
            managed.append(
                {  # type: ignore[arg-type]
                    "Fn::Sub": f"arn:aws:iam::${{AWS::AccountId}}:policy{_join_path(ref.path, ref.name)}"
                }
            )
        if managed:
            props["ManagedPolicyArns"] = managed

        if ps.inline_policy:
            props["Policies"] = [
                {
                    "PolicyName": f"{role_name}-inline",
                    "PolicyDocument": ps.inline_policy,
                }
            ]

        if self.cfg.permission_boundary_arn:
            props["PermissionsBoundary"] = self.cfg.permission_boundary_arn

        if self.cfg.role_tags:
            props["Tags"] = self._tags_list()

        return {"Type": "AWS::IAM::Role", "Properties": props}

    # ── CloudFormation: entitlements (AWS::AccountAccess::Entitlement) ────────

    def entitlement_to_cfn(
        self, principal_type: str, principal_id: str, role_logical_id: str
    ) -> dict[str, Any]:
        """Build one AWS::AccountAccess::Entitlement resource referencing the
        role created in the same template via Fn::GetAtt (Req 11.x).

        The principal block uses UserId for USER assignments and GroupId for
        GROUP assignments, per the AWS::AccountAccess::Entitlement schema.
        """
        principal_key = "UserId" if principal_type == "USER" else "GroupId"
        return {
            "Type": "AWS::AccountAccess::Entitlement",
            "Properties": {
                "ApplicationArn": self.cfg.aam_application_arn,
                "Entitlement": {
                    "PrincipalRole": {
                        "Principal": {
                            "IdentityCenter": {principal_key: principal_id},
                        },
                        "RoleArn": {"Fn::GetAtt": [role_logical_id, "Arn"]},
                    }
                },
            },
        }

    def _cfn_template(self, inventory: Inventory, role_names: dict[str, str]) -> dict[str, Any]:
        resources: dict[str, Any] = {}

        # Roles, keyed by a deterministic logical id derived from the role name.
        role_logical_by_ps: dict[str, str] = {}
        for ps in inventory.permission_sets:
            role_name = role_names.get(ps.arn)
            if not role_name:
                continue
            logical = _logical_id(role_name)
            role_logical_by_ps[ps.arn] = logical
            resources[logical] = self.role_to_cfn(ps, role_name)

        # Entitlements, one per assignment, wired to the role via Fn::GetAtt.
        # Only emitted when an application ARN is configured (the operator
        # prerequisite); otherwise roles-only output is produced.
        if self.cfg.aam_application_arn:
            seen: set[str] = set()
            for a in inventory.assignments:
                role_logical = role_logical_by_ps.get(a.permission_set_arn)
                if not role_logical:
                    continue
                ent_logical = _entitlement_logical_id(
                    role_logical, a.principal_type, a.principal_id, seen
                )
                resources[ent_logical] = self.entitlement_to_cfn(
                    a.principal_type, a.principal_id, role_logical
                )

        return {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": (
                f"IdC-to-AAM migration roles and entitlements (run {inventory.run_id}). "
                "Generated by the Truffle IdC-to-AAM tool."
            ),
            "Resources": resources,
        }

    # ── Emit ─────────────────────────────────────────────────────────────────

    def generate(self, inventory: Inventory, role_names: dict[str, str]) -> str:
        """Write the combined CloudFormation template to
        <iac_output_dir>/<run_id>/roles.yaml. Returns the written path
        (Req 9.1, 9.7)."""
        import yaml  # lazy import

        out_dir = os.path.join(self.cfg.iac_output_dir, inventory.run_id)
        os.makedirs(out_dir, exist_ok=True)
        yaml_path = os.path.join(out_dir, "roles.yaml")

        try:
            cfn = self._cfn_template(inventory, role_names)
            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(cfn, f, sort_keys=False, default_flow_style=False)

            self.audit.log_success(
                "iac_generated",
                out_dir,
                cloudformation=yaml_path,
                roles=len(role_names),
            )
            return yaml_path
        except Exception as exc:  # noqa: BLE001
            self.audit.log_failure("iac_generated", out_dir, exc)
            raise

    def generate_per_account(self, inventory: Inventory, role_names: dict[str, str]) -> dict[str, str]:
        """Write one CloudFormation template per target account.

        In multi-account scenarios a single template won't work because IAM
        roles must be created in each respective account. This method groups
        assignments by account_id and produces a separate template for each,
        containing only the roles and entitlements relevant to that account.

        Returns a dict of {account_id: yaml_file_path}.
        """
        import yaml  # lazy import

        # Group assignments by account_id
        from collections import defaultdict
        assignments_by_account: dict[str, list] = defaultdict(list)
        for a in inventory.assignments:
            assignments_by_account[a.account_id].append(a)

        # Determine unique accounts (from assignments or fall back to hub)
        accounts = sorted(assignments_by_account.keys())
        if not accounts:
            accounts = [inventory.hub_account_id]

        out_dir = os.path.join(self.cfg.iac_output_dir, inventory.run_id)
        os.makedirs(out_dir, exist_ok=True)

        ps_by_arn = {ps.arn: ps for ps in inventory.permission_sets}
        results: dict[str, str] = {}

        for account_id in accounts:
            account_assignments = assignments_by_account.get(account_id, [])

            # Determine which permission sets are relevant to this account
            ps_arns_for_account = {a.permission_set_arn for a in account_assignments}

            resources: dict[str, Any] = {}
            role_logical_by_ps: dict[str, str] = {}

            for ps_arn in sorted(ps_arns_for_account):
                ps = ps_by_arn.get(ps_arn)
                if not ps:
                    continue
                role_name = role_names.get(ps_arn)
                if not role_name:
                    continue
                logical = _logical_id(role_name)
                role_logical_by_ps[ps_arn] = logical
                resources[logical] = self.role_to_cfn(ps, role_name)

            # Entitlements for this account only
            if self.cfg.aam_application_arn:
                seen: set[str] = set()
                for a in account_assignments:
                    role_logical = role_logical_by_ps.get(a.permission_set_arn)
                    if not role_logical:
                        continue
                    ent_logical = _entitlement_logical_id(
                        role_logical, a.principal_type, a.principal_id, seen
                    )
                    resources[ent_logical] = self.entitlement_to_cfn(
                        a.principal_type, a.principal_id, role_logical
                    )

            if not resources:
                continue

            cfn = {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": (
                    f"IdC-to-AAM migration roles for account {account_id} "
                    f"(run {inventory.run_id}). Generated by the Truffle IdC-to-AAM tool."
                ),
                "Resources": resources,
            }

            yaml_path = os.path.join(out_dir, f"roles_{account_id}.yaml")
            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(cfn, f, sort_keys=False, default_flow_style=False)
            results[account_id] = yaml_path

        self.audit.log_success(
            "iac_per_account_generated",
            out_dir,
            accounts=len(results),
            roles=len(role_names),
        )
        return results

    def results_for(
        self, inventory: Inventory, role_names: dict[str, str]
    ) -> list[RoleCreationResult]:
        """Return RoleCreationResult rows describing each planned role so the
        entitlement phase and mapping report still work in generate-iac mode.

        One result per unique (permission_set, account) pair drawn from the
        assignments (mirrors apply-mode shape). The role ARN uses the
        deploying-account placeholder since the concrete account is determined
        at deploy time.
        """
        pairs = sorted(
            {(a.permission_set_arn, a.account_id) for a in inventory.assignments}
        )
        results: list[RoleCreationResult] = []
        for ps_arn, account_id in pairs:
            role_name = role_names.get(ps_arn)
            if not role_name:
                results.append(
                    RoleCreationResult(
                        permission_set_arn=ps_arn,
                        account_id=account_id,
                        role_name="",
                        role_arn=None,
                        status="FAILED",
                        error_detail="no role name in migration plan for permission set",
                    )
                )
                continue
            role_arn = f"arn:aws:iam::{account_id}:role{_join_path(self.cfg.role_path, role_name)}"
            results.append(
                RoleCreationResult(
                    permission_set_arn=ps_arn,
                    account_id=account_id,
                    role_name=role_name,
                    role_arn=role_arn,
                    status="CREATED",
                    permission_boundary_arn=self.cfg.permission_boundary_arn,
                    error_detail="generated-iac",
                )
            )
        return results


def _join_path(path: str, name: str) -> str:
    """Join an IAM path and name into a canonical ``/path/name`` suffix."""
    p = path if path.startswith("/") else "/" + path
    if not p.endswith("/"):
        p += "/"
    return f"{p}{name}"


def _logical_id(role_name: str) -> str:
    """Derive a CloudFormation-safe logical id from a role name."""
    cleaned = re.sub(r"[^0-9a-zA-Z]", "", role_name)
    if not cleaned:
        cleaned = "Role"
    if cleaned[0].isdigit():
        cleaned = "R" + cleaned
    return cleaned


def _entitlement_logical_id(
    role_logical: str, principal_type: str, principal_id: str, seen: set[str]
) -> str:
    """Derive a unique CloudFormation logical id for an entitlement resource."""
    suffix = re.sub(r"[^0-9a-zA-Z]", "", principal_id)[:12] or "p"
    base = f"{role_logical}Ent{principal_type.title()}{suffix}"
    candidate = base
    n = 1
    while candidate in seen:
        n += 1
        candidate = f"{base}{n}"
    seen.add(candidate)
    return candidate
