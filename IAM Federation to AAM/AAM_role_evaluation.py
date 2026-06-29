#!/usr/bin/env python3
"""
AAM Role Evaluation

Evaluates IAM roles in an AWS account that are configured with SAML-based
federation trust policies. Generates a CSV report of those roles, their
attached/inline policies, and trust policy details.

Reference: https://github.com/aws-samples/migration-evaluator-for-aws-iam-identity-center

Usage:
    python AAM_role_evaluation.py              # Normal run: evaluate + optional update
    python AAM_role_evaluation.py --rollback <backup_file>  # Restore trust policies from backup

Requirements:
    - boto3
    - Valid AWS credentials with IAM permissions:
        iam:ListSAMLProviders, iam:ListRoles, iam:ListAttachedRolePolicies,
        iam:ListRolePolicies, iam:GetRole, iam:UpdateAssumeRolePolicy
"""

import boto3
import json
import csv
import sys
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

iam_client = boto3.client("iam")
iam_resource = boto3.resource("iam")


def get_aws_account_id() -> str:
    """Get the current AWS account ID via STS."""
    return boto3.client("sts").get_caller_identity()["Account"]


def get_saml_providers() -> List[Dict[str, str]]:
    """Return list of SAML provider ARNs and names configured in the account."""
    response = iam_client.list_saml_providers()
    providers = []
    for p in response.get("SAMLProviderList", []):
        arn = p["Arn"]
        # Extract friendly name from ARN (last segment after '/')
        name = arn.split("/")[-1]
        providers.append({"arn": arn, "name": name})
    return providers


def prompt_for_idp(providers: List[Dict[str, str]], account_id: str) -> str:
    """
    Display existing SAML identity providers and let the user pick one,
    or enter a custom ARN or just a provider name. The first non-Identity-Center
    provider is offered as the default.
    """
    if not providers:
        print("No SAML identity providers found in this account.")
        custom = input("Enter the SAML provider ARN or name: ").strip()
        if not custom:
            print("No provider supplied. Exiting.")
            sys.exit(1)
        if not custom.startswith("arn:"):
            custom = f"arn:aws:iam::{account_id}:saml-provider/{custom}"
            print(f"  Constructed ARN: {custom}")
        return custom

    print("\nSAML Identity Providers found in this account:")
    for idx, p in enumerate(providers, start=1):
        label = p["name"]
        if "AWSSSO" in label or "DO_NOT_DELETE" in label:
            label += "  [Identity Center - auto-created]"
        print(f"  {idx}) {label}  ({p['arn']})")

    # Pick the first non-Identity-Center provider as default if possible
    default_idx = 0
    for i, p in enumerate(providers):
        if "AWSSSO" not in p["name"] and "DO_NOT_DELETE" not in p["name"]:
            default_idx = i
            break

    default_arn = providers[default_idx]["arn"]
    print(f"\nDefault: {default_idx + 1}) {providers[default_idx]['name']}")
    choice = input(
        "Select a number, enter a provider name, full ARN, or press Enter for default: "
    ).strip()

    if choice == "":
        return default_arn

    # Numeric selection
    try:
        index = int(choice) - 1
        if 0 <= index < len(providers):
            return providers[index]["arn"]
    except ValueError:
        pass

    # Full ARN
    if choice.startswith("arn:"):
        return choice

    # Bare name — construct the ARN
    constructed = f"arn:aws:iam::{account_id}:saml-provider/{choice}"
    print(f"  Constructed ARN: {constructed}")
    return constructed


def get_all_role_names() -> List[str]:
    """Paginate through all IAM roles and return their names."""
    names = []
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        names.extend(r["RoleName"] for r in page["Roles"])
    return names


def filter_saml_roles(role_names: List[str], idp_arn: str) -> List[Dict[str, Any]]:
    """
    For each role, inspect the trust policy (AssumeRolePolicyDocument).
    Return roles whose trust policy references the given SAML provider ARN.
    Each entry includes the role name and the trust policy statement(s).
    """
    saml_roles = []
    for name in role_names:
        role = iam_resource.Role(name)
        trust_doc = role.assume_role_policy_document
        if not trust_doc:
            continue

        for stmt in trust_doc.get("Statement", []):
            principal = stmt.get("Principal", {})
            federated = principal.get("Federated", "")
            # Federated can be a string or a list
            if isinstance(federated, str):
                federated = [federated]
            if idp_arn in federated:
                saml_roles.append(
                    {"role_name": name, "trust_policy_document": trust_doc}
                )
                break  # no need to check remaining statements

    return saml_roles


def get_attached_policies(role_name: str) -> List[Dict[str, str]]:
    """Return attached managed policies (name + ARN) for a role."""
    policies = []
    paginator = iam_client.get_paginator("list_attached_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for p in page.get("AttachedPolicies", []):
            policies.append(
                {
                    "policy_name": p["PolicyName"],
                    "policy_arn": p["PolicyArn"],
                    "policy_type": "AWS Managed"
                    if p["PolicyArn"].startswith("arn:aws:iam::aws:policy")
                    else "Customer Managed",
                }
            )
    return policies


def get_inline_policies(role_name: str) -> List[Dict[str, str]]:
    """Return inline policy names for a role."""
    policies = []
    paginator = iam_client.get_paginator("list_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for name in page.get("PolicyNames", []):
            policies.append({"policy_name": name, "policy_type": "Inline"})
    return policies


def extract_trust_policy_name(trust_doc: Dict) -> str:
    """
    Build a human-readable summary of who/what is trusted in the
    AssumeRolePolicyDocument.  Returns the federated provider name(s)
    and any conditions (e.g. SAML:aud).
    """
    parts = []
    for stmt in trust_doc.get("Statement", []):
        federated = stmt.get("Principal", {}).get("Federated", "")
        if isinstance(federated, list):
            federated = ", ".join(federated)
        if federated:
            # Use just the provider name portion of the ARN
            provider_name = federated.split("/")[-1] if "/" in federated else federated
            condition = stmt.get("Condition", {})
            condition_str = json.dumps(condition) if condition else ""
            entry = f"Federated:{provider_name}"
            if condition_str:
                entry += f" | Condition:{condition_str}"
            parts.append(entry)
    return "; ".join(parts) if parts else "N/A"


def generate_csv(
    account_id: str,
    idp_arn: str,
    saml_roles: List[Dict[str, Any]],
    output_file: Optional[str] = None,
) -> str:
    """
    Generate a CSV with columns:
        Role Name, Policy Name, Policy Type, Trust Policy Name
    Returns the output file path.
    """
    if output_file is None:
        output_file = f"AAM_role_evaluation_{account_id}.csv"

    header = ["Role Name", "Policy Name", "Policy Type", "Trust Policy Name"]
    rows: List[List[str]] = []

    for entry in saml_roles:
        role_name = entry["role_name"]
        trust_name = extract_trust_policy_name(entry["trust_policy_document"])

        attached = get_attached_policies(role_name)
        inline = get_inline_policies(role_name)
        all_policies = attached + inline

        if all_policies:
            for pol in all_policies:
                rows.append(
                    [role_name, pol["policy_name"], pol["policy_type"], trust_name]
                )
        else:
            # Role has no policies attached — still record it
            rows.append([role_name, "(none)", "N/A", trust_name])

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)

    return output_file


def backup_trust_policies(saml_roles: List[Dict[str, Any]], account_id: str) -> str:
    """
    Save the current trust policy for each role to a timestamped JSON file.
    Returns the backup file path.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"AAM_trust_backup_{account_id}_{timestamp}.json"

    backup_data = {}
    for entry in saml_roles:
        role_name = entry["role_name"]
        # Re-fetch live trust policy to ensure accuracy
        role = iam_resource.Role(role_name)
        role.reload()
        backup_data[role_name] = role.assume_role_policy_document

    with open(backup_file, "w") as f:
        json.dump(backup_data, f, indent=2)

    print(f"  Backup saved: {backup_file}")
    return backup_file


def rollback_trust_policies(backup_file: str) -> None:
    """
    Restore trust policies from a backup JSON file created by backup_trust_policies().
    """
    if not os.path.isfile(backup_file):
        print(f"Backup file not found: {backup_file}")
        sys.exit(1)

    with open(backup_file, "r") as f:
        backup_data = json.load(f)

    print(f"\nRolling back {len(backup_data)} role(s) from {backup_file}")
    confirm = input("Type 'yes' to confirm rollback: ").strip().lower()
    if confirm != "yes":
        print("Rollback aborted.")
        return

    success = 0
    errors = 0
    for role_name, trust_doc in backup_data.items():
        try:
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(trust_doc),
            )
            print(f"  ✓ {role_name}")
            success += 1
        except Exception as e:
            print(f"  ✗ {role_name}: {e}")
            errors += 1

    print(f"\nRollback complete: {success} succeeded, {errors} failed.")


# The new trust policy statement to add to roles
NEW_TRUST_STATEMENT = {
    "Sid": "AAMTrustPolicyStatement",
    "Effect": "Allow",
    "Principal": {
        "Service": "account-access-preview.amazonaws.com"
    },
    "Action": [
        "sts:AssumeRole",
        "sts:SetContext"
    ],
}


def update_trust_policies(saml_roles: List[Dict[str, Any]], idp_arn: str, account_id: str) -> None:
    """
    For each identified SAML role, prompt the user to either:
      1) ADD the new trust statement alongside the existing IDP statement
      2) REPLACE the existing IDP statement with the new trust statement
      3) SKIP — make no changes

    The choice applies to ALL roles (batch operation).
    """
    print("\n" + "=" * 60)
    print("  Trust Policy Update")
    print("=" * 60)
    print("\nNew trust policy statement to apply:")
    print(json.dumps(NEW_TRUST_STATEMENT, indent=2))

    print(f"\nThis will affect {len(saml_roles)} role(s).")
    print("\nOptions:")
    print("  1) ADD    — Keep existing IDP trust statement, add the new statement")
    print("  2) REPLACE — Remove the IDP trust statement, add the new statement")
    print("  3) SKIP   — Do not modify any trust policies")

    choice = ""
    while choice not in ("1", "2", "3"):
        choice = input("\nYour choice [1/2/3]: ").strip()

    if choice == "3":
        print("Skipping trust policy updates.")
        return

    mode = "ADD" if choice == "1" else "REPLACE"
    print(f"\nMode: {mode}")

    # Backup current trust policies before making any changes
    print("\nBacking up current trust policies...")
    backup_file = backup_trust_policies(saml_roles, account_id)
    print(f"  To rollback: python3 AAM_role_evaluation.py --rollback {backup_file}")

    # Confirmation gate
    confirm = input(
        f"\nThis will update {len(saml_roles)} role(s). Type 'yes' to confirm: "
    ).strip().lower()
    if confirm != "yes":
        print("Aborted. No changes made.")
        return

    success = 0
    errors = 0
    skipped = 0
    for entry in saml_roles:
        role_name = entry["role_name"]
        trust_doc = entry["trust_policy_document"]

        # Skip if the role already has our statement (avoids duplicate Sid error)
        existing_sids = {s.get("Sid") for s in trust_doc.get("Statement", [])}
        if NEW_TRUST_STATEMENT["Sid"] in existing_sids:
            print(f"  ⏭ {role_name}: already has Sid '{NEW_TRUST_STATEMENT['Sid']}', skipping")
            skipped += 1
            continue

        if mode == "ADD":
            # Append the new statement to the existing list
            new_doc = dict(trust_doc)
            new_doc["Statement"] = list(trust_doc["Statement"]) + [NEW_TRUST_STATEMENT]
        else:
            # REPLACE: remove statements that reference the old IDP, add the new one
            new_doc = dict(trust_doc)
            kept = []
            for stmt in trust_doc["Statement"]:
                federated = stmt.get("Principal", {}).get("Federated", "")
                if isinstance(federated, str):
                    federated = [federated]
                if idp_arn not in federated:
                    kept.append(stmt)
            kept.append(NEW_TRUST_STATEMENT)
            new_doc["Statement"] = kept

        try:
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(new_doc),
            )
            print(f"  ✓ {role_name}")
            success += 1
        except Exception as e:
            print(f"  ✗ {role_name}: {e}")
            errors += 1

    print(f"\nTrust policy update complete: {success} succeeded, {skipped} skipped, {errors} failed.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Handle --rollback mode
    if len(sys.argv) >= 3 and sys.argv[1] == "--rollback":
        backup_file = sys.argv[2]
        print("=" * 60)
        print("  AAM Role Evaluation — Rollback Mode")
        print("=" * 60)
        rollback_trust_policies(backup_file)
        return

    print("=" * 60)
    print("  AAM Role Evaluation — SAML Federated Role Report")
    print("=" * 60)

    account_id = get_aws_account_id()
    print(f"\nAWS Account: {account_id}")

    # 1. Discover and select the Identity Provider
    providers = get_saml_providers()
    idp_arn = prompt_for_idp(providers, account_id)
    print(f"\nUsing Identity Provider: {idp_arn}")

    # 2. List all roles and filter to SAML-trusted roles
    print("\nRetrieving IAM roles...")
    all_roles = get_all_role_names()
    print(f"  Total roles in account: {len(all_roles)}")

    print("Filtering roles with SAML trust policy for selected IdP...")
    saml_roles = filter_saml_roles(all_roles, idp_arn)
    print(f"  SAML-federated roles found: {len(saml_roles)}")

    if not saml_roles:
        print("\nNo SAML-federated roles found for the selected provider. Nothing to export.")
        sys.exit(0)

    # 3. Generate CSV
    csv_path = generate_csv(account_id, idp_arn, saml_roles)
    print(f"\nCSV report generated: {csv_path}")

    # 4. Optionally update trust policies on the identified roles
    update_trust_policies(saml_roles, idp_arn, account_id)
    print("\nDone.")


if __name__ == "__main__":
    main()
