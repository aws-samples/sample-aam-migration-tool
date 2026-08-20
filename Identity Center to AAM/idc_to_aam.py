#!/usr/bin/env python3
"""IdC-to-AAM Migration Tool — main CLI entry point.

Workflow:
    1. Inventory (read-only): list permission sets and assignments
    2. Migration plan (generate editable XLSX, or consume an edited --plan)
    3. Role + entitlement handling:
         - generate-iac (default) → write a CloudFormation template
           (roles + entitlements). NO change is made to your AWS environment.
         - apply               → after an explicit confirmation, create the IAM
           roles and AAM entitlements live via the API.
    4. Mapping report

Every important action is audit-logged.

Usage:
    python3 idc_to_aam.py --help

See README.md for full usage and IAM permissions.
"""

from __future__ import annotations

import sys
from typing import Sequence

from audit_logger import AuditLogger
from aws_session import assume_spoke_session, get_hub_context
from config import Config, ConfigError, parse_args, validate
from entitlement_creator import EntitlementCreator
from iac_generator import IaCGenerator
from inventory import InventoryModule
from mapping_reporter import MappingReporter
from models import AccountAssignmentRecord, Inventory, PermissionSetRecord
from plan import MigrationPlanModule, PlanError
from role_creator import RoleCreator


def print_inventory_summary(inventory) -> None:
    """Print, in plain language, what was found in the IdC instance."""
    print()
    print("Identity Center inventory")
    print(f"  Instance:        {inventory.idc_instance_arn}")
    print(f"  Permission sets: {len(inventory.permission_sets)}")
    print(f"  Assignments:     {len(inventory.assignments)}")
    if inventory.assignments:
        print()
        print("  Who has access to what:")
        ps_name = {ps.arn: ps.name for ps in inventory.permission_sets}
        for a in inventory.assignments:
            print(
                f"    - {a.principal_type.title()} {a.principal_display_name} "
                f"→ {ps_name.get(a.permission_set_arn, a.permission_set_arn)} "
                f"in account {a.account_id}"
            )
    print()


def confirm_apply(hub_account_id: str, target_accounts: tuple[str, ...] = ()) -> bool:
    """Up-front confirmation shown before anything runs in apply mode, because
    apply is the only path that changes the live AWS environment (Req 13)."""
    print()
    print("\u26a0\ufe0f  This will make changes to your AWS environment.")
    if target_accounts and len(target_accounts) > 1:
        print(f"   It will create IAM roles and AAM entitlements in {len(target_accounts)} accounts:")
        for acct in target_accounts:
            print(f"     - {acct}")
    else:
        acct = target_accounts[0] if target_accounts else hub_account_id
        print(f"   It will create IAM roles and AAM entitlements in account {acct}.")
    try:
        ans = input("   Are you sure you want to continue? Type 'yes' to proceed: ").strip().lower()
    except EOFError:
        return False
    return ans in ("yes", "y")


def main(argv: Sequence[str]) -> int:
    try:
        cfg = parse_args(argv)
        validate(cfg)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if cfg.out_of_scope_request:
        print(cfg.out_of_scope_request, file=sys.stderr)
        return 2

    hub = get_hub_context(region=cfg.region)
    apply_mode = cfg.role_creation_mode == "apply"

    # ── Apply-only: skip discovery, load from a previous inventory file ───────
    if cfg.apply_only:
        if not cfg.inventory_input:
            print("ERROR: --inventory-input is required with --apply-only", file=sys.stderr)
            return 2
        if not cfg.trust_policy_path:
            print("ERROR: --trust-policy is required with --apply-only", file=sys.stderr)
            return 2

        import json as _json
        print(f"Loading inventory from: {cfg.inventory_input}")
        with open(cfg.inventory_input, "r", encoding="utf-8") as f:
            inv_data = _json.load(f)

        # Reconstruct an Inventory from the JSON
        inventory = Inventory.from_json_data(inv_data) if hasattr(Inventory, "from_json_data") else Inventory(
            hub_account_id=inv_data.get("hub_account_id", hub.account_id),
            idc_instance_arn=inv_data.get("idc_instance_arn", ""),
            identity_store_id=inv_data.get("identity_store_id", ""),
            permission_sets=tuple(
                PermissionSetRecord(
                    arn=ps.get("arn", ""),
                    name=ps.get("name", ""),
                    description=ps.get("description", ""),
                    session_duration=ps.get("session_duration", "PT1H"),
                    inline_policy=ps.get("inline_policy"),
                    aws_managed_policy_arns=tuple(p.get("arn", "") for p in ps.get("aws_managed_policy_arns", ps.get("aws_managed_policies", []))),
                    customer_managed_policy_references=tuple(),
                    permission_boundary=None,
                ) for ps in inv_data.get("permission_sets", [])
            ),
            assignments=tuple(
                AccountAssignmentRecord(
                    permission_set_arn=a.get("permission_set_arn", ""),
                    account_id=a.get("account_id", ""),
                    principal_type=a.get("principal_type", ""),
                    principal_id=a.get("principal_id", ""),
                    principal_display_name=a.get("principal_display_name", ""),
                ) for a in inv_data.get("assignments", [])
            ),
            run_id=cfg.run_id,
            captured_at=inv_data.get("captured_at", ""),
        )
        print(f"  {len(inventory.permission_sets)} permission set(s), {len(inventory.assignments)} assignment(s)")

        # Force apply mode for --apply-only
        apply_mode = True
        # Skip confirmation prompt or honor --auto-approve
        if not cfg.auto_approve:
            if not confirm_apply(hub.account_id, cfg.account_ids):
                print("Cancelled. No changes were made.")
                return 0
    else:
        # Normal flow: ask up front, then run discovery
        if apply_mode and not cfg.auto_approve:
            if not confirm_apply(hub.account_id, cfg.account_ids):
                print("Cancelled. No changes were made to your AWS environment.")
                return 0

    audit = AuditLogger(run_id=cfg.run_id, caller_arn=hub.caller_arn, cfg=cfg)
    audit.log_success(
        "run_started",
        cfg.run_id,
        hub_account=hub.account_id,
        account_scope=cfg.account_scope,
        role_creation_mode=cfg.role_creation_mode,
    )

    try:
        # ── Phase 2 (early): Consume plan if provided ────────────────────────
        # When a plan is supplied, we parse it first so we can run targeted
        # discovery (only the permission sets + accounts in the plan).
        plan_module = MigrationPlanModule(cfg, audit)
        plan_rows = None
        role_names: dict[str, str] = {}
        if cfg.plan_path:
            try:
                plan_rows = plan_module.consume(cfg.plan_path)
                role_names = plan_module.role_name_for(plan_rows)
            except PlanError as exc:
                audit.log_failure("migration_plan", cfg.plan_path or cfg.run_id, exc)
                print(f"Migration plan error: {exc}", file=sys.stderr)
                return 2

        # ── Phase 1: Inventory ────────────────────────────────────────────────
        if cfg.apply_only:
            # Already loaded above from --inventory-input
            pass
        elif plan_rows:
            # Plan-supplied path: run targeted discovery using only the PS ARNs
            # and account IDs from the plan. IdC remains the source of truth for
            # assignments (who has access) — the plan only controls which
            # permission sets and accounts are in scope.
            target_ps_arns = list(role_names.keys())
            target_accounts_from_plan: list[str] = []
            for row in plan_rows:
                for acct in row.account_ids:
                    if acct not in target_accounts_from_plan:
                        target_accounts_from_plan.append(acct)

            inventory = InventoryModule(hub, cfg, audit).run(
                ps_arns_override=target_ps_arns,
                account_ids_override=target_accounts_from_plan or None,
            )
            print_inventory_summary(inventory)
        else:
            inventory = InventoryModule(hub, cfg, audit).run()
            print_inventory_summary(inventory)

        # ── Phase 2 (continued): Generate plan if not supplied ────────────────
        if not plan_rows:
            try:
                plan_module.generate(inventory, cfg.plan_output_path)
                plan_rows = plan_module.rows_from_inventory(inventory)
                role_names = plan_module.role_name_for(plan_rows)
            except PlanError as exc:
                audit.log_failure("migration_plan", cfg.plan_path or cfg.run_id, exc)
                print(f"Migration plan error: {exc}", file=sys.stderr)
                return 2

        # ── Scope the inventory to the supplied plan ──────────────────────────
        # When the operator provides a plan, it is authoritative: only the
        # permission sets, accounts, and principals it lists are migrated. This
        # prevents a broad saved inventory (e.g. a full-org discovery) from
        # creating roles/entitlements the operator did not review in the plan.
        # (Auto-generated plans mirror the full inventory, so this is skipped.)
        if cfg.plan_path:
            before = len(inventory.assignments)
            inventory = plan_module.filter_inventory(inventory, plan_rows)
            after = len(inventory.assignments)
            if after != before:
                print(
                    f"  Scoped to migration plan: {after} of {before} assignment(s) "
                    f"match the plan and will be migrated."
                )

        iac_generator = IaCGenerator(cfg, audit)

        # Build a profile→account_id mapping if profiles were provided
        profile_to_account: dict[str, str] = {}
        account_to_profile: dict[str, str] = {}
        if cfg.profiles:
            import boto3 as _boto3
            for profile in cfg.profiles:
                try:
                    sess = _boto3.Session(profile_name=profile, region_name=cfg.region)
                    acct = sess.client("sts").get_caller_identity()["Account"]
                    profile_to_account[profile] = acct
                    account_to_profile[acct] = profile
                except Exception as exc:
                    print(f"  Warning: could not resolve profile '{profile}': {exc}")

        def session_factory(account_id: str):
            if cfg.account_scope == "single":
                return hub.session
            # If profiles are provided, use the matching profile for this account
            if account_to_profile and account_id in account_to_profile:
                import boto3 as _boto3
                return _boto3.Session(profile_name=account_to_profile[account_id], region_name=cfg.region)
            # If the account is the hub account, reuse the hub session
            if account_id == hub.account_id:
                return hub.session
            # Otherwise assume role
            return assume_spoke_session(
                account_id=account_id,
                role_name=cfg.role_name or "OrganizationAccountAccessRole",
                run_id=cfg.run_id,
                region=cfg.region,
                workers=cfg.workers,
            )

        role_creator = RoleCreator(
            cfg, audit, session_factory, role_names, iac_generator=iac_generator
        )
        ent_creator = EntitlementCreator(hub, cfg, audit)

        # ── Phase 3: Role creation (apply = live IAM; generate-iac = template) ─
        role_results = role_creator.run(inventory)

        # ── Phase 4: Entitlements (apply = live AAM; generate-iac = in template)
        application, entitlement_results = ent_creator.run(inventory, role_results)

        # ── Mapping report ───────────────────────────────────────────────────
        reporter = MappingReporter(cfg, audit)
        rows = reporter.build_rows(inventory, role_results, application, entitlement_results)
        report_path = reporter.write(rows)

        audit.log_success(
            "run_complete",
            cfg.run_id,
            mode=cfg.role_creation_mode,
            roles=len(role_results),
            entitlements_created=sum(1 for e in entitlement_results if e.status == "CREATED"),
            entitlements_existing=sum(1 for e in entitlement_results if e.status == "EXISTING"),
            entitlements_skipped=sum(1 for e in entitlement_results if e.status == "SKIPPED"),
            entitlements_failed=sum(1 for e in entitlement_results if e.status == "FAILED"),
        )

        # ── Closing message ───────────────────────────────────────────────────
        print()
        if apply_mode:
            created = sum(1 for e in entitlement_results if e.status == "CREATED")
            print(
                f"Done. Created/verified {len(role_results)} role(s) and "
                f"{created} new entitlement(s) in account {hub.account_id}."
            )
        else:
            cfn_path = f"{cfg.iac_output_dir}/{cfg.run_id}/roles.yaml"
            print("No changes were made to your AWS environment.")
            print(f"Review the CloudFormation template: {cfn_path}")
            print("Deploy it yourself, or re-run with --role-creation-mode apply to apply live.")
        if report_path:
            print(f"Mapping report: {report_path}")
        print()
        return 0
    except KeyboardInterrupt:
        audit.log_failure("run_interrupted", cfg.run_id, KeyboardInterrupt())
        return 130
    except Exception as exc:  # noqa: BLE001 - surface unexpected failures
        audit.log_failure("run_failed", cfg.run_id, exc)
        print(f"Run failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        audit.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
