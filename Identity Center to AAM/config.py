"""CLI argument parsing and validation for the IdC-to-AAM Migration Tool."""

from __future__ import annotations

import argparse
import os
import re
import uuid
from dataclasses import dataclass, field
from typing import Sequence


# ─── Errors ───────────────────────────────────────────────────────────────────

class ConfigError(ValueError):
    """Raised when CLI configuration is invalid."""


# ─── Out-of-scope redirects (Req 16.5) ────────────────────────────────────────

_OUT_OF_SCOPE_REDIRECTS = {
    "scan-resource-policies": (
        "Resource-based policy scanning is handled by the resource_policy_scan "
        "utility at truffle/Utilites/resource_policy_scan/. Run "
        "`python3 scan_resource_policies.py --help` from that directory."
    ),
    "iam-federation": (
        "IAM Federation (SAML) migration is handled by the IAM Federation to AAM "
        "component at truffle/IAM Federation to AAM/. See its README for usage."
    ),
    "scp-analysis": (
        "Service control policy / resource control policy / VPC endpoint policy "
        "analysis is out of scope for the IdC-to-AAM tool. See "
        "truffle/Utilites/ for related guidance."
    ),
}


# ─── Config dataclass ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Config:
    # Account targeting
    account_scope: str  # "single" | "multi" | "org"
    account_ids: tuple[str, ...]
    role_name: str | None
    profiles: tuple[str, ...]  # AWS profile names for multi-account (alternative to assume-role)
    # Mode
    auto_approve: bool
    apply_only: bool
    inventory_input: str | None
    role_creation_mode: str  # "apply" | "generate-iac"
    # Role creation
    role_name_template: str  # default-name generator for the migration plan only
    role_path: str
    role_tags: dict[str, str]
    trust_policy_path: str | None
    permission_boundary_arn: str | None
    convert_inline_to_cmp: bool
    cmp_name_template: str
    # Migration plan
    plan_path: str | None
    plan_output_path: str | None
    # IaC
    iac_output_dir: str
    # AAM
    aam_application_arn: str | None
    validate_aam_application: bool
    aam_idc_instance_arn: str | None
    aam_region: str | None
    # Audit
    audit_to_cloudwatch: bool
    cloudwatch_log_group: str | None
    audit_to_file: bool
    audit_file_path: str | None
    # Output
    inventory_output_path: str | None
    mapping_output_format: str  # XLSX | CSV | JSON
    mapping_output_path: str | None
    # Concurrency
    workers: int
    verbose: bool
    # Identifiers
    run_id: str
    # Out-of-scope
    out_of_scope_request: str | None
    # Region
    region: str

    @property
    def account_ids_list(self) -> list[str]:
        return list(self.account_ids)


# ─── Parsing ──────────────────────────────────────────────────────────────────

def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


def _parse_tags(values: Sequence[str] | None) -> dict[str, str]:
    if not values:
        return {}
    out: dict[str, str] = {}
    for v in values:
        if "=" not in v:
            raise ConfigError(f"Tag '{v}' must be in Key=Value form")
        key, val = v.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not key:
            raise ConfigError(f"Tag '{v}' has empty key")
        out[key] = val
    return out


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="idc_to_aam",
        description=(
            "Migrate AWS IAM Identity Center (IdC) configuration to "
            "Account Access Manager (AAM). Inventories permission sets, "
            "recreates them as IAM roles in target accounts, and creates "
            "AAM entitlements that mirror IdC assignments."
        ),
    )

    # Account targeting
    p.add_argument(
        "--account-scope",
        choices=["single", "multi", "org"],
        default="single",
        help=(
            "Run against a single account (the hub, using current credentials), "
            "multiple specified accounts (assume-role into each target), or the "
            "entire organization (scans all provisioned accounts). Default: single."
        ),
    )
    p.add_argument(
        "--account-ids",
        help=(
            "Comma-separated AWS account IDs. Defines which accounts to discover "
            "permission sets/assignments for AND where to create roles in apply mode."
        ),
    )
    p.add_argument(
        "--role-name",
        help="Name of the IAM role to AssumeRole into in each target account (for multi with assume-role).",
    )
    p.add_argument(
        "--profiles",
        help=(
            "Comma-separated AWS profile names for multi-account role creation. "
            "Each profile is resolved to its account via GetCallerIdentity. "
            "Alternative to --account-ids + --role-name."
        ),
    )

    # Mode
    p.add_argument(
        "--auto-approve",
        action="store_true",
        help="Skip the confirmation prompt before applying changes (apply mode).",
    )
    p.add_argument(
        "--apply-only",
        action="store_true",
        help=(
            "Skip discovery. Create roles + entitlements directly from a previously "
            "generated inventory JSON (--inventory-input). Requires --trust-policy "
            "and --aam-application-arn."
        ),
    )
    p.add_argument(
        "--inventory-input",
        help="Path to a previously generated inventory JSON file (for --apply-only).",
    )
    p.add_argument(
        "--role-creation-mode",
        choices=["apply", "generate-iac"],
        default="generate-iac",
        help=(
            "How to create roles: 'generate-iac' (default) reads your environment "
            "and writes a CloudFormation template (roles + AAM entitlements) without "
            "making any change to AWS; 'apply' creates the IAM roles and AAM "
            "entitlements live via the API."
        ),
    )

    # Role creation
    p.add_argument(
        "--role-name-template",
        default="AAM-{permission_set_name}",
        help="Template for new role names. Variables: {permission_set_name}.",
    )
    p.add_argument(
        "--role-path",
        default="/aam/",
        help='IAM role path for new roles (default "/aam/").',
    )
    p.add_argument(
        "--tag",
        dest="tags",
        action="append",
        help="Tag to apply to every created role, in Key=Value form. Repeatable.",
    )
    p.add_argument(
        "--trust-policy",
        dest="trust_policy_path",
        help="Path to JSON file containing the AssumeRolePolicyDocument for new roles.",
    )
    p.add_argument(
        "--permission-boundary",
        dest="permission_boundary_arn",
        help="ARN of an IAM permission boundary to attach to every created role.",
    )
    p.add_argument(
        "--convert-inline-to-cmp",
        action="store_true",
        help=(
            "Convert each permission set's inline policy to a customer managed "
            "policy in the target account before attaching."
        ),
    )
    p.add_argument(
        "--cmp-name-template",
        default="AAM-{permission_set_name}-inline",
        help="Template for the converted CMP name when --convert-inline-to-cmp.",
    )

    # Migration plan
    p.add_argument(
        "--plan",
        dest="plan_path",
        help=(
            "Path to an edited migration plan XLSX to consume. When omitted, the "
            "tool generates a plan from the inventory using default role names."
        ),
    )
    p.add_argument(
        "--plan-output",
        dest="plan_output_path",
        help="Path for the generated migration plan XLSX (when --plan is not supplied).",
    )

    # IaC
    p.add_argument(
        "--iac-output-dir",
        dest="iac_output_dir",
        default="output",
        help=(
            "Base directory for generated IaC. The CloudFormation template is "
            "written to <dir>/<run_id>/roles.yaml. Default: output."
        ),
    )

    # AAM
    p.add_argument(
        "--aam-application-arn",
        dest="aam_application_arn",
        help=(
            "ARN of the pre-existing, operator-managed AAM application to create "
            "entitlements against. Required in apply mode; in generate-iac mode it "
            "is optional (when supplied, entitlement resources are added to the "
            "template)."
        ),
    )
    p.add_argument(
        "--validate-aam-application",
        action="store_true",
        help="Verify the supplied AAM application exists via GetApplication before use.",
    )
    p.add_argument(
        "--aam-idc-instance-arn",
        help="Override IdC instance ARN. Auto-discovered if not supplied.",
    )

    # Audit
    p.add_argument(
        "--audit-to-cloudwatch",
        action="store_true",
        help="Emit audit log entries to CloudWatch Logs.",
    )
    p.add_argument("--cloudwatch-log-group", help="CloudWatch log group name.")
    p.add_argument(
        "--audit-to-file",
        action="store_true",
        help="Append audit log entries to a CSV file.",
    )
    p.add_argument("--audit-file-path", help="Path for the audit CSV file.")

    # Output
    p.add_argument(
        "--inventory-output",
        dest="inventory_output_path",
        help="Path for the inventory JSON file.",
    )
    p.add_argument(
        "--mapping-format",
        dest="mapping_output_format",
        choices=["XLSX", "CSV", "JSON"],
        default="XLSX",
        help="Format of the mapping report (default XLSX).",
    )
    p.add_argument(
        "--mapping-output",
        dest="mapping_output_path",
        help="Path for the mapping report.",
    )

    # Concurrency
    p.add_argument(
        "--workers",
        type=int,
        default=5,
        help="Maximum concurrent worker threads (default 5).",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Print the full structured audit log (JSON) to the console. By "
            "default the console stays clean and only failures are shown on stderr."
        ),
    )

    # Region
    p.add_argument(
        "--region",
        default=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        help="AWS region (default us-east-1 or AWS_DEFAULT_REGION).",
    )

    # Hidden out-of-scope detectors (kept for backwards compatibility but hidden from --help)
    p.add_argument(
        "--scan-resource-policies",
        dest="out_of_scope_scan_resource_policies",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    p.add_argument(
        "--migrate-iam-federation",
        dest="out_of_scope_iam_federation",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    p.add_argument(
        "--analyze-scps",
        dest="out_of_scope_scp_analysis",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    return p


def _extract_region_from_arn(arn: str | None) -> str | None:
    """Extract the region from an ARN like arn:aws:account-access:us-west-2:..."""
    if not arn:
        return None
    parts = arn.split(":")
    if len(parts) >= 4 and parts[3]:
        return parts[3]
    return None


def parse_args(argv: Sequence[str]) -> Config:
    parser = _build_parser()
    ns = parser.parse_args(list(argv))

    # Detect out-of-scope flags first so the orchestrator can short-circuit.
    out_of_scope: str | None = None
    if getattr(ns, "out_of_scope_scan_resource_policies", False):
        out_of_scope = _OUT_OF_SCOPE_REDIRECTS["scan-resource-policies"]
    elif getattr(ns, "out_of_scope_iam_federation", False):
        out_of_scope = _OUT_OF_SCOPE_REDIRECTS["iam-federation"]
    elif getattr(ns, "out_of_scope_scp_analysis", False):
        out_of_scope = _OUT_OF_SCOPE_REDIRECTS["scp-analysis"]

    cfg = Config(
        account_scope=ns.account_scope,
        account_ids=tuple(_split_csv(ns.account_ids)),
        role_name=ns.role_name,
        profiles=tuple(_split_csv(getattr(ns, "profiles", None))),
        auto_approve=bool(ns.auto_approve),
        apply_only=bool(getattr(ns, "apply_only", False)),
        inventory_input=getattr(ns, "inventory_input", None),
        role_creation_mode=ns.role_creation_mode,
        role_name_template=ns.role_name_template,
        role_path=ns.role_path,
        role_tags=_parse_tags(ns.tags),
        trust_policy_path=ns.trust_policy_path,
        permission_boundary_arn=ns.permission_boundary_arn,
        convert_inline_to_cmp=bool(ns.convert_inline_to_cmp),
        cmp_name_template=ns.cmp_name_template,
        plan_path=ns.plan_path,
        plan_output_path=ns.plan_output_path,
        iac_output_dir=ns.iac_output_dir,
        aam_application_arn=ns.aam_application_arn,
        validate_aam_application=bool(ns.validate_aam_application),
        aam_idc_instance_arn=ns.aam_idc_instance_arn,
        aam_region=_extract_region_from_arn(ns.aam_application_arn),
        audit_to_cloudwatch=bool(ns.audit_to_cloudwatch),
        cloudwatch_log_group=ns.cloudwatch_log_group,
        audit_to_file=bool(ns.audit_to_file),
        audit_file_path=ns.audit_file_path,
        inventory_output_path=ns.inventory_output_path,
        mapping_output_format=ns.mapping_output_format,
        mapping_output_path=ns.mapping_output_path,
        workers=int(ns.workers),
        verbose=bool(ns.verbose),
        run_id=uuid.uuid4().hex,
        out_of_scope_request=out_of_scope,
        region=ns.region,
    )
    return cfg


# ─── Validation ───────────────────────────────────────────────────────────────

_TEMPLATE_VAR_RE = re.compile(r"{permission_set_name}")
_ROLE_PATH_RE = re.compile(r"\A/[A-Za-z0-9+=,.@_-]*(?:/[A-Za-z0-9+=,.@_-]+)*/?\Z")


def validate(cfg: Config) -> None:
    """Validate configuration. Raises ConfigError on invalid combinations.

    Both modes require a trust policy (it defines the roles). Apply mode also
    requires the operator-supplied AAM application ARN, since it creates
    entitlements live; in generate-iac mode the ARN is optional (when present
    the entitlement resources are emitted into the template, otherwise a
    roles-only template is produced). (Req 5.5, 9.1, 16.5)
    """
    if cfg.workers < 1:
        raise ConfigError("--workers must be >= 1")
    if cfg.mapping_output_format not in ("XLSX", "CSV", "JSON"):
        raise ConfigError(
            f"--mapping-format must be XLSX|CSV|JSON, got {cfg.mapping_output_format!r}"
        )
    if not _TEMPLATE_VAR_RE.search(cfg.role_name_template):
        raise ConfigError(
            "--role-name-template must contain the {permission_set_name} variable"
        )
    if cfg.convert_inline_to_cmp and not _TEMPLATE_VAR_RE.search(cfg.cmp_name_template):
        raise ConfigError(
            "--cmp-name-template must contain the {permission_set_name} variable "
            "when --convert-inline-to-cmp is set"
        )
    if not _ROLE_PATH_RE.match(cfg.role_path):
        raise ConfigError(
            f"--role-path {cfg.role_path!r} must match IAM path format (start and end with '/')"
        )

    # Role-creation mode (Req 7.1).
    if cfg.role_creation_mode not in ("apply", "generate-iac"):
        raise ConfigError(
            f"--role-creation-mode must be 'apply' or 'generate-iac', "
            f"got {cfg.role_creation_mode!r}"
        )

    # Account scope validation (Req 1.1, 1.6-1.9).
    if cfg.account_scope not in ("single", "multi", "org"):
        raise ConfigError(
            f"--account-scope must be 'single', 'multi', or 'org', got {cfg.account_scope!r}"
        )
    if cfg.account_scope == "multi":
        # Multi-account requires --account-ids for discovery (to know which
        # accounts to query permission sets for).
        if not cfg.account_ids:
            raise ConfigError(
                "--account-ids is required when --account-scope is 'multi' "
                "(specifies which accounts to discover permission sets for)"
            )
        # For apply mode, also need credentials for target accounts
        if cfg.role_creation_mode == "apply":
            if not cfg.profiles and not cfg.role_name:
                raise ConfigError(
                    "apply mode with --account-scope multi requires either "
                    "--profiles or --role-name to authenticate into target accounts"
                )
    # Out-of-scope short-circuit: skip the role/AAM checks (Req 16.5).
    if cfg.out_of_scope_request:
        return

    # A trust policy defines the roles in both modes (live CreateRole in apply,
    # the AssumeRolePolicyDocument in the CloudFormation template in generate-iac).
    if not cfg.trust_policy_path:
        raise ConfigError(
            "--trust-policy is required (it defines the AssumeRolePolicyDocument "
            "for the AAM-assumable roles)"
        )
    if not os.path.isfile(cfg.trust_policy_path):
        raise ConfigError(
            f"--trust-policy path does not exist or is not a file: {cfg.trust_policy_path}"
        )

    # The AAM application is an operator-managed prerequisite. Apply mode creates
    # entitlements live, so it requires the ARN. Generate-iac mode emits the
    # entitlement resources only when the ARN is supplied (otherwise roles-only).
    if cfg.role_creation_mode == "apply" and not cfg.aam_application_arn:
        raise ConfigError(
            "--aam-application-arn is required in apply mode "
            "(the AAM application is an operator-managed prerequisite; the tool "
            "creates entitlements against it but never creates the application)"
        )

    # Audit sink validation (Req 16.1, 16.2, 16.3).
    if cfg.audit_to_cloudwatch and not cfg.cloudwatch_log_group:
        raise ConfigError("--cloudwatch-log-group is required when --audit-to-cloudwatch")
    if cfg.audit_to_file and not cfg.audit_file_path:
        raise ConfigError("--audit-file-path is required when --audit-to-file")


def render_role_name(template: str, permission_set_name: str) -> str:
    """Apply the role name template (Req 5.1, 6.2)."""
    return template.format(permission_set_name=permission_set_name)


def render_cmp_name(template: str, permission_set_name: str) -> str:
    """Apply the CMP name template (Req 5.7)."""
    return template.format(permission_set_name=permission_set_name)
