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
import defusedcsv as csv
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


def prompt_for_idp(providers: List[Dict[str, str]], account_id: str) -> List[str]:
    """
    Display existing SAML identity providers and let the user pick one or more.
    Supports comma-separated numbers (e.g., "1,3"), a single number, a full ARN,
    or a provider name. Returns a list of ARNs.
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
        return [custom]

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
        "Select number(s) (comma-separated for multiple), a provider name, full ARN, or Enter for default: "
    ).strip()

    if choice == "":
        return [default_arn]

    # Comma-separated numeric selections (e.g., "1,3" or "2, 4")
    if all(part.strip().isdigit() for part in choice.split(",")):
        selected = []
        for part in choice.split(","):
            index = int(part.strip()) - 1
            if 0 <= index < len(providers):
                selected.append(providers[index]["arn"])
        if selected:
            return selected

    # Single numeric selection
    try:
        index = int(choice) - 1
        if 0 <= index < len(providers):
            return [providers[index]["arn"]]
    except ValueError:
        pass

    # Full ARN
    if choice.startswith("arn:"):
        return [choice]

    # Bare name — construct the ARN
    constructed = f"arn:aws:iam::{account_id}:saml-provider/{choice}"
    print(f"  Constructed ARN: {constructed}")
    return [constructed]


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

    with open(output_file, "w", newline="", encoding="utf-8") as f:
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

    with open(backup_file, "w", encoding="utf-8") as f:
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

    with open(backup_file, "r", encoding="utf-8") as f:
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
        "Service": "account-access.amazonaws.com"
    },
    "Action": [
        "sts:AssumeRole",
        "sts:SetContext"
    ],
}

AAM_SERVICE_PRINCIPALS = {"account-access.amazonaws.com", "account-access-preview.amazonaws.com"}


def update_trust_policies(saml_roles: List[Dict[str, Any]], idp_arns: List[str], account_id: str) -> None:
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

        # Skip if the role already has the AAM service principal
        already_has_aam = False
        for stmt in trust_doc.get("Statement", []):
            svc = stmt.get("Principal", {}).get("Service", "")
            if isinstance(svc, str):
                svc = [svc]
            if any(s in AAM_SERVICE_PRINCIPALS for s in svc):
                already_has_aam = True
                break
        if already_has_aam:
            print(f"  ⏭ {role_name}: already has AAM service principal, skipping")
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
                # Keep statements that don't reference any of the selected IDPs
                if not any(idp in federated for idp in idp_arns):
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
# Parallelized role filtering — delegates to lib.py
# ---------------------------------------------------------------------------

from lib import (
    list_saml_providers as _lib_list_providers,
    list_all_role_names as _lib_list_role_names,
    discover_federated_roles as _lib_discover_roles,
    migrate_roles_parallel as _lib_migrate_parallel,
    create_entitlements as _lib_create_entitlements,
    parse_entitlement_csv as _lib_parse_csv,
    NEW_TRUST_STATEMENT,
)


def filter_saml_roles_parallel(
    role_names: List[str], idp_arns: List[str] | str, workers: int = 5, session: Optional[Any] = None
) -> List[Dict[str, Any]]:
    """Parallel discovery using the shared library. Falls back to global session."""
    if session is None:
        session = boto3.Session()
    account_id = session.client("sts").get_caller_identity()["Account"]
    return _lib_discover_roles(session, role_names, idp_arns, account_id, workers=workers)


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
# Entitlement creation — delegates to lib.py
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
    AAM entitlements via the shared library.
    """
    import re

    with open(group_names_file, "r", encoding="utf-8") as f:
        groups = [line.strip() for line in f if line.strip()]

    if not groups:
        print("  No group names found in file.")
        return

    escaped = group_pattern.replace("{principal}", "(?P<principal>.+?)")
    escaped = escaped.replace("{account}", "(?P<account>\\d+)")
    escaped = escaped.replace("{role}", "(?P<role>.+)")
    regex = re.compile(f"^{escaped}$")

    role_lookup = {r["role_name"]: r for r in saml_roles}
    role_lookup_lower = {r["role_name"].lower(): r for r in saml_roles}

    mappings = []
    for g in groups:
        match = regex.match(g)
        if match:
            d = match.groupdict()
            role_name = d.get("role", "")
            matched_role = role_lookup.get(role_name) or role_lookup_lower.get(role_name.lower())
            if matched_role:
                mappings.append({
                    "group": g,
                    "principal": d.get("principal", ""),
                    "account": d.get("account", account_id),
                    "role": role_name,
                    "matchedRoleArn": matched_role.get("role_arn") or f"arn:aws:iam::{d.get('account', account_id)}:role/{role_name}",
                })

    print(f"\n  Parsed {len(groups)} group(s), {len(mappings)} matched to discovered roles.")
    if not mappings:
        print("  No matches to create entitlements for.")
        return

    print(f"\n  Creating {len(mappings)} entitlement(s) against {aam_application_arn}")
    hub_session = boto3.Session()
    results = _lib_create_entitlements(
        hub_session, aam_application_arn, mappings, region=region, workers=workers,
    )

    for r in results:
        if r["status"] == "created":
            print(f"  \u2713 {r.get('group', '')} \u2192 {r.get('role_arn', '')}")
        elif r["status"] == "already exists":
            print(f"  \u23ed {r.get('group', '')} (already exists)")
        else:
            print(f"  \u2717 {r.get('group', '')}: {r.get('error', '')}")

    success = len([r for r in results if r["status"] == "created"])
    existing = len([r for r in results if r["status"] == "already exists"])
    errors = len([r for r in results if r["status"] == "error"])
    print(f"\n  Entitlement creation complete: {success} created, {existing} existing, {errors} failed.")


def create_entitlements_from_csv(
    aam_application_arn: str,
    csv_path: str,
    region: str = "us-east-1",
    workers: int = 5,
) -> None:
    """Create entitlements from a columnar CSV file via the shared library."""
    try:
        mappings = _lib_parse_csv(csv_path)
    except ValueError as exc:
        print(f"  ERROR: {exc}")
        return
    if not mappings:
        print("  No valid mappings in CSV.")
        return

    print(f"\n  Creating {len(mappings)} entitlement(s) from CSV against {aam_application_arn}")
    hub_session = boto3.Session()
    results = _lib_create_entitlements(
        hub_session, aam_application_arn, mappings, region=region, workers=workers,
    )

    for r in results:
        if r["status"] == "created":
            print(f"  \u2713 {r.get('group', '')} \u2192 {r.get('role_arn', '')}")
        elif r["status"] == "already exists":
            print(f"  \u23ed {r.get('group', '')} (already exists)")
        else:
            print(f"  \u2717 {r.get('group', '')}: {r.get('error', '')}")

    success = len([r for r in results if r["status"] == "created"])
    existing = len([r for r in results if r["status"] == "already exists"])
    errors = len([r for r in results if r["status"] == "error"])
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
                        help="single: current account. multi: use profiles or assume-role into each target.")
    parser.add_argument("--account-ids", help="Comma-separated target account IDs (for multi with assume-role).")
    parser.add_argument("--role-name", help="Role name to assume in each target account (for multi with assume-role).")
    parser.add_argument("--profiles", help="Comma-separated AWS profile names (for multi with profiles). Each profile is resolved to its account via GetCallerIdentity.")
    parser.add_argument("--workers", type=int, default=5, help="Max parallel workers (default 5).")
    parser.add_argument("--aam-application-arn", help="AAM application ARN for entitlement creation.")
    parser.add_argument("--apply-only", action="store_true",
                        help="Skip discovery. Apply trust policy updates + entitlement creation directly from --entitlement-csv. Requires --aam-application-arn and --entitlement-csv.")
    parser.add_argument("--mode", choices=["ADD", "REPLACE"], default="ADD",
                        help="Trust policy update mode for --apply-only. ADD (default): keep SAML trust, add AAM. REPLACE: remove SAML trust.")
    parser.add_argument("--group-names-file", help="File with IdP group names (one per line) for entitlement mapping.")
    parser.add_argument("--group-pattern", default="{principal}_{account}_{role}",
                        help="Pattern to parse group names. Placeholders: {principal}, {account}, {role}.")
    parser.add_argument("--entitlement-csv", help="Columnar CSV with Group, Account, Role columns for direct entitlement mapping (alternative to --group-names-file).")
    parser.add_argument("--region", default="us-east-1", help="AWS region for AAM calls.")

    args = parser.parse_args()

    # Handle --rollback mode
    if args.rollback:
        print("=" * 60)
        print("  AAM Role Evaluation — Rollback Mode")
        print("=" * 60)
        rollback_trust_policies(args.rollback)
        return

    # Handle --apply-only mode (skip discovery, apply directly from CSV)
    if args.apply_only:
        if not args.entitlement_csv:
            print("ERROR: --entitlement-csv is required with --apply-only")
            sys.exit(1)
        if not args.aam_application_arn:
            print("ERROR: --aam-application-arn is required with --apply-only")
            sys.exit(1)

        print("=" * 60)
        print("  AAM Role Evaluation — Apply Only Mode")
        print("=" * 60)

        # Parse the CSV
        try:
            mappings = _lib_parse_csv(args.entitlement_csv)
        except ValueError as exc:
            print(f"ERROR: {exc}")
            sys.exit(1)
        print(f"\n  Loaded {len(mappings)} mapping(s) from {args.entitlement_csv}")

        if not mappings:
            print("  No valid mappings found. Exiting.")
            return

        # Step 1: Update trust policies on the roles referenced in the CSV
        role_arns = list({m["matchedRoleArn"] for m in mappings if m.get("matchedRoleArn")})
        if role_arns:
            print(f"\n  Updating trust policies on {len(role_arns)} role(s) ({args.mode} mode)...")

            # Build session map — resolve from profiles or assume-role
            session_map: Dict[str, Any] = {}
            if args.profiles:
                for profile in [p.strip() for p in args.profiles.split(",") if p.strip()]:
                    try:
                        s = boto3.Session(profile_name=profile)
                        acct = s.client("sts").get_caller_identity()["Account"]
                        session_map[acct] = s
                    except Exception as exc:
                        print(f"    WARNING: Profile '{profile}' failed: {exc}")
            elif args.account_ids and args.role_name:
                for acct in [a.strip() for a in args.account_ids.split(",") if a.strip()]:
                    try:
                        session_map[acct] = assume_role_session(acct, args.role_name)
                    except Exception as exc:
                        print(f"    WARNING: Could not assume into {acct}: {exc}")
            else:
                # Single account — use default session
                default_session = boto3.Session()
                default_acct = default_session.client("sts").get_caller_identity()["Account"]
                session_map[default_acct] = default_session

            # Backup current trust policies before modification
            print("  Backing up current trust policies...")
            backup_data = {}
            for role_arn in role_arns:
                parts = role_arn.split(":")
                acct = parts[4] if len(parts) >= 5 else ""
                rn = role_arn.split("/")[-1]
                s = session_map.get(acct) or next(iter(session_map.values()), None)
                if s:
                    try:
                        resp = s.client("iam").get_role(RoleName=rn)
                        backup_data[rn] = resp["Role"]["AssumeRolePolicyDocument"]
                    except Exception:
                        pass
            if backup_data:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file = f"AAM_trust_backup_apply_only_{timestamp}.json"
                with open(backup_file, "w", encoding="utf-8") as f:
                    json.dump(backup_data, f, indent=2)
                print(f"  Backup saved: {backup_file}")
                print(f"  To rollback: python3 AAM_role_evaluation.py --rollback {backup_file}")

            # Apply trust policy updates
            results = _lib_migrate_parallel(
                session_map, role_arns, args.mode, "",
                workers=args.workers,
            )
            success = len([r for r in results if r["status"] == "success"])
            skipped = len([r for r in results if r["status"] == "skipped"])
            errors = len([r for r in results if r["status"] == "error"])
            print(f"  Trust policy update: {success} succeeded, {skipped} skipped, {errors} failed.")

        # Step 2: Create entitlements
        print(f"\n  Creating entitlements...")
        create_entitlements_from_csv(
            args.aam_application_arn, args.entitlement_csv, args.region, args.workers,
        )

        print("\nDone.")
        return

    print("=" * 60)
    print("  AAM Role Evaluation — SAML Federated Role Report")
    print("=" * 60)

    # Multi-account support
    if args.account_scope == "multi":
        if not args.account_ids and not args.profiles:
            print("ERROR: --account-ids (with --role-name) or --profiles is required for --account-scope multi")
            sys.exit(1)

        # Resolve sessions: either from profiles or assume-role
        account_sessions = []  # list of (label, session, account_id)
        if args.profiles:
            # Profile mode: resolve each profile to its account
            for profile in [p.strip() for p in args.profiles.split(",") if p.strip()]:
                try:
                    session = boto3.Session(profile_name=profile)
                    acct = session.client("sts").get_caller_identity()["Account"]
                    account_sessions.append((profile, session, acct))
                    print(f"  Profile '{profile}' → account {acct}")
                except Exception as exc:
                    print(f"  ERROR: Profile '{profile}' failed: {exc}")
        else:
            # Assume-role mode
            if not args.role_name:
                print("ERROR: --role-name is required when using --account-ids")
                sys.exit(1)
            account_ids = [a.strip() for a in args.account_ids.split(",") if a.strip()]
            for acct in account_ids:
                try:
                    session = assume_role_session(acct, args.role_name)
                    account_sessions.append((acct, session, acct))
                except Exception as exc:
                    print(f"  ERROR: Could not assume role in {acct}: {exc}")

        all_saml_roles = []
        for label, session, account_id in account_sessions:
            print(f"\n{'='*60}")
            print(f"  Account: {account_id} ({label})")
            print(f"{'='*60}")

            # Override global clients for this account
            global iam_client, iam_resource
            iam_client = session.client("iam")
            iam_resource = session.resource("iam")

            providers = get_saml_providers()
            idp_arns = prompt_for_idp(providers, account_id)
            print(f"\n  Using Identity Provider(s): {', '.join(idp_arns)}")

            all_roles = get_all_role_names()
            print(f"  Total roles: {len(all_roles)}")

            print(f"  Filtering (parallel, {args.workers} workers)...")
            saml_roles = filter_saml_roles_parallel(all_roles, idp_arns, args.workers, session)
            print(f"  SAML-federated roles found: {len(saml_roles)}")

            if saml_roles:
                csv_path = generate_csv(account_id, idp_arns[0], saml_roles)
                print(f"  CSV: {csv_path}")
                update_trust_policies(saml_roles, idp_arns, account_id)
                all_saml_roles.extend(saml_roles)

        # Entitlement creation (after all accounts processed)
        if args.aam_application_arn and all_saml_roles:
            print("\n" + "=" * 60)
            print("  AAM Entitlement Creation")
            print("=" * 60)
            first_account = account_sessions[0][2] if account_sessions else ""
            if args.entitlement_csv:
                create_entitlements_from_csv(
                    args.aam_application_arn, args.entitlement_csv, args.region, args.workers,
                )
            elif args.group_names_file:
                create_entitlements_from_groups(
                    all_saml_roles, first_account, args.aam_application_arn,
                    args.group_names_file, args.group_pattern, args.region, args.workers,
                )
        print("\nDone.")
        return

    # Single account mode
    account_id = get_aws_account_id()
    print(f"\nAWS Account: {account_id}")

    providers = get_saml_providers()
    idp_arns = prompt_for_idp(providers, account_id)
    print(f"\nUsing Identity Provider(s): {', '.join(idp_arns)}")

    print("\nRetrieving IAM roles...")
    all_roles = get_all_role_names()
    print(f"  Total roles in account: {len(all_roles)}")

    print(f"Filtering roles (parallel, {args.workers} workers)...")
    saml_roles = filter_saml_roles_parallel(all_roles, idp_arns, args.workers)
    print(f"  SAML-federated roles found: {len(saml_roles)}")

    if not saml_roles:
        print("\nNo SAML-federated roles found for the selected provider. Nothing to export.")
        sys.exit(0)

    csv_path = generate_csv(account_id, idp_arns[0], saml_roles)
    print(f"\nCSV report generated: {csv_path}")

    update_trust_policies(saml_roles, idp_arns, account_id)

    # Entitlement creation
    if args.aam_application_arn:
        print("\n" + "=" * 60)
        print("  AAM Entitlement Creation")
        print("=" * 60)
        if args.entitlement_csv:
            create_entitlements_from_csv(
                args.aam_application_arn, args.entitlement_csv, args.region, args.workers,
            )
        elif args.group_names_file:
            create_entitlements_from_groups(
                saml_roles, account_id, args.aam_application_arn,
                args.group_names_file, args.group_pattern, args.region, args.workers,
            )

    print("\nDone.")


if __name__ == "__main__":
    main()
