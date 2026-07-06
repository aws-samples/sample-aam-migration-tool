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
from typing import List, Dict, Any, Optional, Optional

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
# Parallelized role filtering
# ---------------------------------------------------------------------------

def filter_saml_roles_parallel(
    role_names: List[str], idp_arn: str, workers: int = 5
) -> List[Dict[str, Any]]:
    """Parallel version of filter_saml_roles using ThreadPoolExecutor."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    saml_roles = []
    done = 0
    total = len(role_names)

    def inspect(name: str) -> Optional[Dict[str, Any]]:
        role = iam_resource.Role(name)
        trust_doc = role.assume_role_policy_document
        if not trust_doc:
            return None
        for stmt in trust_doc.get("Statement", []):
            principal = stmt.get("Principal", {})
            federated = principal.get("Federated", "")
            if isinstance(federated, str):
                federated = [federated]
            if idp_arn in federated:
                return {"role_name": name, "trust_policy_document": trust_doc}
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(inspect, name): name for name in role_names}
        for fut in as_completed(futures):
            done += 1
            if done % 20 == 0:
                print(f"    Inspected {done}/{total} roles...")
            try:
                result = fut.result()
                if result:
                    saml_roles.append(result)
            except Exception:
                pass

    return saml_roles


# ---------------------------------------------------------------------------
# Multi-account support
# ---------------------------------------------------------------------------

def assume_role_session(account_id: str, role_name: str) -> "boto3.Session":
    """Assume a role in a target account and return a session."""
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    print(f"  Assuming role: {role_arn}")
    sts = boto3.client("sts")
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="aam-fed-eval")["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


# ---------------------------------------------------------------------------
# Entitlement creation
# ---------------------------------------------------------------------------

def create_entitlements_from_groups(
    saml_roles: List[Dict[str, Any]],
    account_id: str,
    aam_application_arn: str,
    group_names_file: str,
    group_pattern: str,
    region: str = "us-east-1",
    workers: int = 5,
) -> None:
    """
    Parse group names using the pattern, match to discovered roles, and create
    AAM entitlements.
    """
    import re
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Read group names
    with open(group_names_file, "r") as f:
        groups = [line.strip() for line in f if line.strip()]

    if not groups:
        print("  No group names found in file.")
        return

    # Build regex from pattern
    escaped = group_pattern.replace("{principal}", "(?P<principal>.+?)")
    escaped = escaped.replace("{account}", "(?P<account>\\d+)")
    escaped = escaped.replace("{role}", "(?P<role>.+)")
    regex = re.compile(f"^{escaped}$")

    # Build role name lookup
    role_lookup = {r["role_name"]: r for r in saml_roles}
    role_lookup_lower = {r["role_name"].lower(): r for r in saml_roles}

    # Parse and match
    mappings = []
    for g in groups:
        match = regex.match(g)
        if match:
            d = match.groupdict()
            role_name = d.get("role", "")
            matched_role = role_lookup.get(role_name) or role_lookup_lower.get(role_name.lower())
            mappings.append({
                "group": g,
                "principal": d.get("principal", ""),
                "account": d.get("account", ""),
                "role_name": role_name,
                "matched": matched_role is not None,
                "role_arn": f"arn:aws:iam::{d.get('account', account_id)}:role/{role_name}" if matched_role else None,
            })
        else:
            mappings.append({"group": g, "principal": None, "account": None, "role_name": None, "matched": False, "role_arn": None})

    matched = [m for m in mappings if m["matched"] and m["role_arn"]]
    print(f"\n  Parsed {len(mappings)} group(s), {len(matched)} matched to discovered roles.")

    if not matched:
        print("  No matches to create entitlements for.")
        return

    # Create AAM client with preview endpoint
    aam_endpoint = f"https://account-access-preview.{region}.api.aws"
    try:
        aam_client = boto3.client("accountaccess", region_name=region, endpoint_url=aam_endpoint)
    except Exception as exc:
        print(f"  ERROR: Could not create AAM client: {exc}")
        return

    print(f"\n  Creating {len(matched)} entitlement(s) against {aam_application_arn}")
    success = 0
    errors = 0
    existing = 0

    def create_one(m):
        principal_block = {"groupId": m["principal"]}
        try:
            aam_client.create_entitlement(
                applicationArn=aam_application_arn,
                entitlement={
                    "principalRole": {
                        "principal": {"identityCenter": principal_block},
                        "roleArn": m["role_arn"],
                    }
                },
            )
            return "created"
        except Exception as exc:
            if "Conflict" in str(exc) or "AlreadyExists" in str(exc):
                return "existing"
            return f"error: {exc}"

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(create_one, m): m for m in matched}
        for fut in as_completed(futures):
            m = futures[fut]
            result = fut.result()
            if result == "created":
                print(f"  ✓ {m['group']} → {m['role_arn']}")
                success += 1
            elif result == "existing":
                print(f"  ⏭ {m['group']} (already exists)")
                existing += 1
            else:
                print(f"  ✗ {m['group']}: {result}")
                errors += 1

    print(f"\n  Entitlement creation complete: {success} created, {existing} existing, {errors} failed.")


# ---------------------------------------------------------------------------
# Main (updated with new flags)
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Evaluate and migrate SAML-federated IAM roles to AAM."
    )
    parser.add_argument("--rollback", help="Rollback trust policies from a backup file.")
    parser.add_argument("--account-scope", choices=["single", "multi"], default="single",
                        help="single: current account. multi: assume into each target account.")
    parser.add_argument("--account-ids", help="Comma-separated target account IDs (required for multi).")
    parser.add_argument("--role-name", help="Role name to assume in each target account (required for multi).")
    parser.add_argument("--workers", type=int, default=5, help="Max parallel workers (default 5).")
    parser.add_argument("--aam-application-arn", help="AAM application ARN for entitlement creation.")
    parser.add_argument("--group-names-file", help="File with IdP group names (one per line) for entitlement mapping.")
    parser.add_argument("--group-pattern", default="{principal}_{account}_{role}",
                        help="Pattern to parse group names. Placeholders: {principal}, {account}, {role}.")
    parser.add_argument("--region", default="us-east-1", help="AWS region for AAM calls.")

    args = parser.parse_args()

    # Handle --rollback mode
    if args.rollback:
        print("=" * 60)
        print("  AAM Role Evaluation — Rollback Mode")
        print("=" * 60)
        rollback_trust_policies(args.rollback)
        return

    print("=" * 60)
    print("  AAM Role Evaluation — SAML Federated Role Report")
    print("=" * 60)

    # Multi-account support
    if args.account_scope == "multi":
        if not args.account_ids or not args.role_name:
            print("ERROR: --account-ids and --role-name are required for --account-scope multi")
            sys.exit(1)
        account_ids = [a.strip() for a in args.account_ids.split(",") if a.strip()]
        all_saml_roles = []
        for acct in account_ids:
            print(f"\n{'='*60}")
            print(f"  Account: {acct}")
            print(f"{'='*60}")
            try:
                session = assume_role_session(acct, args.role_name)
                # Override global clients for this account
                global iam_client, iam_resource
                iam_client = session.client("iam")
                iam_resource = session.resource("iam")
                account_id = acct
            except Exception as exc:
                print(f"  ERROR: Could not assume role in {acct}: {exc}")
                continue

            providers = get_saml_providers()
            idp_arn = prompt_for_idp(providers, account_id)
            print(f"\n  Using Identity Provider: {idp_arn}")

            all_roles = get_all_role_names()
            print(f"  Total roles: {len(all_roles)}")

            print(f"  Filtering (parallel, {args.workers} workers)...")
            saml_roles = filter_saml_roles_parallel(all_roles, idp_arn, args.workers)
            print(f"  SAML-federated roles found: {len(saml_roles)}")

            if saml_roles:
                csv_path = generate_csv(account_id, idp_arn, saml_roles)
                print(f"  CSV: {csv_path}")
                update_trust_policies(saml_roles, idp_arn, account_id)
                all_saml_roles.extend(saml_roles)

        # Entitlement creation (after all accounts processed)
        if args.aam_application_arn and args.group_names_file and all_saml_roles:
            print("\n" + "=" * 60)
            print("  AAM Entitlement Creation")
            print("=" * 60)
            create_entitlements_from_groups(
                all_saml_roles, account_ids[0], args.aam_application_arn,
                args.group_names_file, args.group_pattern, args.region, args.workers,
            )
        print("\nDone.")
        return

    # Single account mode
    account_id = get_aws_account_id()
    print(f"\nAWS Account: {account_id}")

    providers = get_saml_providers()
    idp_arn = prompt_for_idp(providers, account_id)
    print(f"\nUsing Identity Provider: {idp_arn}")

    print("\nRetrieving IAM roles...")
    all_roles = get_all_role_names()
    print(f"  Total roles in account: {len(all_roles)}")

    print(f"Filtering roles (parallel, {args.workers} workers)...")
    saml_roles = filter_saml_roles_parallel(all_roles, idp_arn, args.workers)
    print(f"  SAML-federated roles found: {len(saml_roles)}")

    if not saml_roles:
        print("\nNo SAML-federated roles found for the selected provider. Nothing to export.")
        sys.exit(0)

    csv_path = generate_csv(account_id, idp_arn, saml_roles)
    print(f"\nCSV report generated: {csv_path}")

    update_trust_policies(saml_roles, idp_arn, account_id)

    # Entitlement creation
    if args.aam_application_arn and args.group_names_file:
        print("\n" + "=" * 60)
        print("  AAM Entitlement Creation")
        print("=" * 60)
        create_entitlements_from_groups(
            saml_roles, account_id, args.aam_application_arn,
            args.group_names_file, args.group_pattern, args.region, args.workers,
        )

    print("\nDone.")


if __name__ == "__main__":
    main()
