"""Data models for the IdC-to-AAM Migration Tool.

All collections use immutable tuples so every record is hashable and friendly
to property-based testing with Hypothesis.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Literal


PrincipalType = Literal["USER", "GROUP"]
RowStatus = Literal["CREATED", "SKIPPED", "FAILED", "EXISTING"]
LogStatus = Literal["SUCCESS", "FAILURE"]


# ─── IdC inventory records ────────────────────────────────────────────────────

@dataclass(frozen=True)
class CustomerManagedPolicyReference:
    name: str
    path: str  # IAM policy path, e.g. "/" or "/foo/"


@dataclass(frozen=True)
class PermissionSetRecord:
    arn: str
    name: str
    description: str
    session_duration: str  # ISO 8601 duration, e.g. "PT1H"
    inline_policy: dict | None
    aws_managed_policy_arns: tuple[str, ...]
    customer_managed_policy_references: tuple[CustomerManagedPolicyReference, ...]
    permission_boundary: dict | None
    incomplete: bool = False
    error_reason: str = ""


@dataclass(frozen=True)
class AccountAssignmentRecord:
    permission_set_arn: str
    account_id: str
    principal_type: PrincipalType
    principal_id: str
    principal_display_name: str  # falls back to principal_id (Req 3.4)


@dataclass(frozen=True)
class MigrationPlanRow:
    """One row of the editable migration plan (Req 5).

    `permission_set_arn` is the authoritative key; `role_name` is the editable
    target IAM role name (default ``AAM-<PermissionSetName>``). `principals` and
    `account_ids` are informational context shown to the operator only.
    """

    permission_set_arn: str
    permission_set_name: str
    role_name: str
    principals: tuple[str, ...] = ()
    account_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Inventory:
    hub_account_id: str
    idc_instance_arn: str
    identity_store_id: str
    permission_sets: tuple[PermissionSetRecord, ...]
    assignments: tuple[AccountAssignmentRecord, ...]
    run_id: str
    captured_at: str  # ISO 8601 timestamp

    # ── Serialization helpers ────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "hub_account_id": self.hub_account_id,
            "idc_instance_arn": self.idc_instance_arn,
            "identity_store_id": self.identity_store_id,
            "run_id": self.run_id,
            "captured_at": self.captured_at,
            "permission_sets": [
                {
                    "arn": ps.arn,
                    "name": ps.name,
                    "description": ps.description,
                    "session_duration": ps.session_duration,
                    "inline_policy": ps.inline_policy,
                    "aws_managed_policy_arns": list(ps.aws_managed_policy_arns),
                    "customer_managed_policy_references": [
                        asdict(ref) for ref in ps.customer_managed_policy_references
                    ],
                    "permission_boundary": ps.permission_boundary,
                    "incomplete": ps.incomplete,
                    "error_reason": ps.error_reason,
                }
                for ps in self.permission_sets
            ],
            "assignments": [asdict(a) for a in self.assignments],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Inventory":
        permission_sets = tuple(
            PermissionSetRecord(
                arn=ps["arn"],
                name=ps["name"],
                description=ps["description"],
                session_duration=ps["session_duration"],
                inline_policy=ps["inline_policy"],
                aws_managed_policy_arns=tuple(ps["aws_managed_policy_arns"]),
                customer_managed_policy_references=tuple(
                    CustomerManagedPolicyReference(**ref)
                    for ref in ps["customer_managed_policy_references"]
                ),
                permission_boundary=ps["permission_boundary"],
                incomplete=ps.get("incomplete", False),
                error_reason=ps.get("error_reason", ""),
            )
            for ps in data["permission_sets"]
        )
        assignments = tuple(
            AccountAssignmentRecord(**a) for a in data["assignments"]
        )
        return cls(
            hub_account_id=data["hub_account_id"],
            idc_instance_arn=data["idc_instance_arn"],
            identity_store_id=data["identity_store_id"],
            permission_sets=permission_sets,
            assignments=assignments,
            run_id=data["run_id"],
            captured_at=data["captured_at"],
        )

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)


# ─── Mutation results ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RoleCreationResult:
    permission_set_arn: str
    account_id: str
    role_name: str
    role_arn: str | None
    status: RowStatus
    attached_managed_policies: tuple[str, ...] = ()
    inline_policy_attached: bool = False
    converted_cmp_arn: str | None = None
    attached_cmp_arns: tuple[str, ...] = ()
    permission_boundary_arn: str | None = None
    error_detail: str = ""


@dataclass(frozen=True)
class ApplicationResult:
    """Describes the operator-supplied (and optionally validated) AAM application.

    The tool never creates the application (Req 10.4, 10.7); it only references
    the ARN passed via ``--aam-application-arn`` and optionally validates it via
    GetApplication. ``status`` is one of SUPPLIED | VALIDATED | FAILED | SKIPPED.
    """

    application_arn: str | None
    status: str  # SUPPLIED | VALIDATED | FAILED | SKIPPED (generate-iac / not applied)
    idc_instance_arn: str
    validated: bool = False
    error_detail: str = ""


@dataclass(frozen=True)
class EntitlementCreationResult:
    application_arn: str
    permission_set_arn: str
    account_id: str
    principal_type: PrincipalType
    principal_id: str
    role_arn: str | None
    entitlement_id: str | None
    status: RowStatus
    error_detail: str = ""


# ─── Reporting ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class MappingReportRow:
    principal_type: PrincipalType
    principal_display_name: str
    principal_id: str
    permission_set_name: str
    permission_set_arn: str
    target_account_id: str
    role_arn: str | None
    application_id: str | None
    entitlement_id: str | None
    status: RowStatus

    @staticmethod
    def header() -> tuple[str, ...]:
        return (
            "principal_type",
            "principal_display_name",
            "principal_id",
            "permission_set_name",
            "permission_set_arn",
            "target_account_id",
            "role_arn",
            "application_id",
            "entitlement_id",
            "status",
        )

    def as_row(self) -> tuple[str, ...]:
        return (
            self.principal_type,
            self.principal_display_name,
            self.principal_id,
            self.permission_set_name,
            self.permission_set_arn,
            self.target_account_id,
            self.role_arn or "",
            self.application_id or "",
            self.entitlement_id or "",
            self.status,
        )


# ─── Audit ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AuditLogEntry:
    timestamp: str  # ISO 8601 with timezone
    run_id: str
    action: str
    target: str
    status: LogStatus
    caller_arn: str
    error_detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "action": self.action,
            "target": self.target,
            "status": self.status,
            "caller_arn": self.caller_arn,
            "error_detail": self.error_detail,
            "extra": self.extra,
        }
