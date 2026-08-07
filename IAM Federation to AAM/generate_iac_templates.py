#!/usr/bin/env python3
"""
Generate CloudFormation and Terraform templates from AAM role evaluation CSV.

Reads the CSV produced by AAM_role_evaluation.py and generates IaC templates.
Uses dict-based template construction + yaml.safe_dump for valid output.

Usage:
    python generate_iac_templates.py <csv_file>
"""

import csv
import json
import os
import re
import sys
from collections import defaultdict
from typing import Any, Dict, List

import yaml


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sanitize_logical_id(name: str) -> str:
    """Convert a role name to a valid CloudFormation logical ID (alphanumeric only)."""
    cleaned = re.sub(r"[^a-zA-Z0-9]", "", name)
    if not cleaned or cleaned[0].isdigit():
        cleaned = "R" + cleaned
    return cleaned


def sanitize_tf_resource_name(name: str) -> str:
    """Convert a role name to a valid Terraform resource name (lowercase, underscores)."""
    return re.sub(r"[^a-z0-9_]", "_", name.lower())


def parse_csv(csv_file: str) -> Dict[str, List[Dict[str, str]]]:
    """
    Parse the evaluation CSV and group policies by role name.
    Returns: {role_name: [{"policy_name": ..., "policy_type": ...}, ...]}
    """
    roles: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            role_name = row["Role Name"].strip()
            policy_name = row["Policy Name"].strip()
            policy_type = row["Policy Type"].strip()
            if policy_name != "(none)":
                roles[role_name].append(
                    {"policy_name": policy_name, "policy_type": policy_type}
                )
            else:
                if role_name not in roles:
                    roles[role_name] = []
    return dict(roles)


# ---------------------------------------------------------------------------
# CloudFormation Generation (dict-based)
# ---------------------------------------------------------------------------

def generate_cloudformation(
    roles: Dict[str, List[Dict[str, str]]],
    output_file: str,
    aam_source_account: str = "",
    aam_application_arn: str = "",
    entitlement_mappings: List[Dict[str, str]] = None,
    resolved_principals: Dict[str, str] = None,
) -> None:
    """Generate a CloudFormation YAML template for the roles and entitlements."""
    if entitlement_mappings is None:
        entitlement_mappings = []
    if resolved_principals is None:
        resolved_principals = {}

    # Parameters
    parameters: Dict[str, Any] = {
        "TrustServicePrincipal": {
            "Type": "String",
            "Default": "account-access.amazonaws.com",
            "Description": "The service principal for the new trust relationship.",
        },
    }
    if aam_source_account:
        parameters["AAMSourceAccount"] = {
            "Type": "String",
            "Default": aam_source_account,
            "Description": "AWS account where AAM is configured (confused-deputy protection).",
        }
    if aam_application_arn:
        parameters["AAMApplicationArn"] = {
            "Type": "String",
            "Default": aam_application_arn,
            "Description": "AAM application ARN (confused-deputy protection).",
        }

    # Trust policy statement
    trust_statement: Dict[str, Any] = {
        "Sid": "AAMTrustPolicyStatement",
        "Effect": "Allow",
        "Principal": {"Service": {"Ref": "TrustServicePrincipal"}},
        "Action": ["sts:AssumeRole", "sts:SetContext"],
    }
    if aam_source_account or aam_application_arn:
        condition: Dict[str, Any] = {"StringEquals": {}}
        if aam_source_account:
            condition["StringEquals"]["aws:SourceAccount"] = {"Ref": "AAMSourceAccount"}
        if aam_application_arn:
            condition["StringEquals"]["aws:SourceArn"] = {"Ref": "AAMApplicationArn"}
        trust_statement["Condition"] = condition

    # Resources — roles
    resources: Dict[str, Any] = {}
    for role_name, policies in roles.items():
        logical_id = sanitize_logical_id(role_name) + "Role"
        role_props: Dict[str, Any] = {
            "RoleName": role_name,
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [trust_statement],
            },
            "Tags": [{"Key": "ManagedBy", "Value": "AAM-Migration"}],
        }

        managed = [p for p in policies if p["policy_type"] != "Inline"]
        if managed:
            managed_arns: List[Any] = []
            for p in managed:
                if p["policy_type"] == "AWS Managed":
                    managed_arns.append(f"arn:aws:iam::aws:policy/{p['policy_name']}")
                else:
                    managed_arns.append({"Fn::Sub": f"arn:aws:iam::${{AWS::AccountId}}:policy/{p['policy_name']}"})
            role_props["ManagedPolicyArns"] = managed_arns

        inline = [p for p in policies if p["policy_type"] == "Inline"]
        if inline:
            role_props["Policies"] = [{
                "PolicyName": p["policy_name"],
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": "*"}],
                },
            } for p in inline]

        resources[logical_id] = {"Type": "AWS::IAM::Role", "Properties": role_props}

    # Resources — entitlements
    if aam_application_arn and entitlement_mappings:
        seen: set = set()
        for i, m in enumerate(entitlement_mappings):
            group = m.get("group", "")
            role_arn = m.get("matchedRoleArn", "")
            principal_type = m.get("principal_type", "GROUP")
            if not group or not role_arn:
                continue
            principal_id = resolved_principals.get(group, group)
            id_key = "UserId" if principal_type.upper() == "USER" else "GroupId"
            logical = sanitize_logical_id(f"{group}{i}") + "Ent"
            while logical in seen:
                logical += "x"
            seen.add(logical)
            resources[logical] = {
                "Type": "AWS::AccountAccess::Entitlement",
                "Properties": {
                    "ApplicationArn": aam_application_arn,
                    "Entitlement": {
                        "PrincipalRole": {
                            "Principal": {"IdentityCenter": {id_key: principal_id}},
                            "RoleArn": role_arn,
                        },
                    },
                },
            }

    # Outputs
    outputs: Dict[str, Any] = {}
    for role_name in roles:
        logical_id = sanitize_logical_id(role_name) + "Role"
        outputs[f"{logical_id}Arn"] = {
            "Description": f"ARN of {role_name}",
            "Value": {"Fn::GetAtt": [logical_id, "Arn"]},
        }

    # Assemble template
    template: Dict[str, Any] = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "IAM roles migrated from SAML federation to AAM. Generated by Truffle.",
    }
    if parameters:
        template["Parameters"] = parameters
    template["Resources"] = resources
    if outputs:
        template["Outputs"] = outputs

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(template, f, sort_keys=False, default_flow_style=False)

    print(f"  CloudFormation template: {output_file}")


# ---------------------------------------------------------------------------
# Terraform Generation
# ---------------------------------------------------------------------------

def generate_terraform(
    roles: Dict[str, List[Dict[str, str]]],
    output_file: str,
    aam_source_account: str = "",
    aam_application_arn: str = "",
) -> None:
    """Generate a Terraform configuration file for the roles."""
    lines = []
    lines.append('# Generated by generate_iac_templates.py')
    lines.append('# IAM roles migrated from SAML federation to AAM trust policy.')
    lines.append('')
    lines.append('variable "trust_service_principal" {')
    lines.append('  description = "The service principal for the new trust relationship"')
    lines.append('  type        = string')
    lines.append('  default     = "account-access.amazonaws.com"')
    lines.append('}')
    if aam_source_account:
        lines.append('')
        lines.append('variable "aam_source_account" {')
        lines.append('  description = "AWS account where AAM is configured (confused-deputy protection)"')
        lines.append('  type        = string')
        lines.append(f'  default     = "{aam_source_account}"')
        lines.append('}')
    if aam_application_arn:
        lines.append('')
        lines.append('variable "aam_application_arn" {')
        lines.append('  description = "AAM application ARN (confused-deputy protection)"')
        lines.append('  type        = string')
        lines.append(f'  default     = "{aam_application_arn}"')
        lines.append('}')
    lines.append('')
    lines.append('data "aws_caller_identity" "current" {}')
    lines.append('')

    # Trust policy document (shared)
    lines.append('data "aws_iam_policy_document" "aam_trust" {')
    lines.append('  statement {')
    lines.append('    sid     = "AAMTrustPolicyStatement"')
    lines.append('    effect  = "Allow"')
    lines.append('    actions = ["sts:AssumeRole", "sts:SetContext"]')
    lines.append('')
    lines.append('    principals {')
    lines.append('      type        = "Service"')
    lines.append('      identifiers = [var.trust_service_principal]')
    lines.append('    }')
    if aam_source_account:
        lines.append('')
        lines.append('    condition {')
        lines.append('      test     = "StringEquals"')
        lines.append('      variable = "aws:SourceAccount"')
        lines.append('      values   = [var.aam_source_account]')
        lines.append('    }')
    if aam_application_arn:
        lines.append('')
        lines.append('    condition {')
        lines.append('      test     = "StringEquals"')
        lines.append('      variable = "aws:SourceArn"')
        lines.append('      values   = [var.aam_application_arn]')
        lines.append('    }')
    lines.append('  }')
    lines.append('}')
    lines.append('')

    for role_name, policies in roles.items():
        tf_name = sanitize_tf_resource_name(role_name)
        lines.append(f'resource "aws_iam_role" "{tf_name}" {{')
        lines.append(f'  name               = "{role_name}"')
        lines.append('  assume_role_policy = data.aws_iam_policy_document.aam_trust.json')
        lines.append('')
        lines.append('  tags = {')
        lines.append('    ManagedBy = "AAM-Migration"')
        lines.append('  }')
        lines.append('}')
        lines.append('')

        managed = [p for p in policies if p["policy_type"] != "Inline"]
        for i, p in enumerate(managed):
            attachment_name = f"{tf_name}_attach_{i}"
            if p["policy_type"] == "AWS Managed":
                arn = f"arn:aws:iam::aws:policy/{p['policy_name']}"
            else:
                arn = f"arn:aws:iam::${{data.aws_caller_identity.current.account_id}}:policy/{p['policy_name']}"
            lines.append(f'resource "aws_iam_role_policy_attachment" "{attachment_name}" {{')
            lines.append(f'  role       = aws_iam_role.{tf_name}.name')
            lines.append(f'  policy_arn = "{arn}"')
            lines.append('}')
            lines.append('')

        inline = [p for p in policies if p["policy_type"] == "Inline"]
        for p in inline:
            inline_tf_name = sanitize_tf_resource_name(p["policy_name"])
            lines.append(f'resource "aws_iam_role_policy" "{tf_name}_{inline_tf_name}" {{')
            lines.append(f'  name   = "{p["policy_name"]}"')
            lines.append(f'  role   = aws_iam_role.{tf_name}.id')
            lines.append('  policy = jsonencode({')
            lines.append('    Version = "2012-10-17"')
            lines.append('    Statement = [{')
            lines.append('      Effect   = "Allow"')
            lines.append('      Action   = ["*"]')
            lines.append('      Resource = "*"')
            lines.append('    }]')
            lines.append('  })')
            lines.append('}')
            lines.append('')

    # Outputs
    lines.append('# Outputs')
    for role_name in roles:
        tf_name = sanitize_tf_resource_name(role_name)
        lines.append(f'output "{tf_name}_arn" {{')
        lines.append(f'  description = "ARN of {role_name}"')
        lines.append(f'  value       = aws_iam_role.{tf_name}.arn')
        lines.append('}')
        lines.append('')

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"  Terraform template:     {output_file}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_iac_templates.py <csv_file>")
        print("Example: python generate_iac_templates.py AAM_role_evaluation_760560298386.csv")
        sys.exit(1)

    csv_file = sys.argv[1]
    if not os.path.isfile(csv_file):
        print(f"Error: File not found: {csv_file}")
        sys.exit(1)

    print(f"Reading: {csv_file}")
    roles = parse_csv(csv_file)
    print(f"  Found {len(roles)} role(s)\n")

    if not roles:
        print("No roles found in CSV. Nothing to generate.")
        sys.exit(0)

    print("Generating IaC templates...")
    generate_cloudformation(roles, "aam_roles_cloudformation.yaml")
    generate_terraform(roles, "aam_roles_terraform.tf")

    print("\nDone. Review the generated files and update any inline policy placeholders")
    print("before deploying.")


if __name__ == "__main__":
    main()
