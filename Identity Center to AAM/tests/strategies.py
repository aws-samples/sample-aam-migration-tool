"""Hypothesis strategies for the IdC-to-AAM data models."""

from __future__ import annotations

import string

from hypothesis import strategies as st

from models import (
    AccountAssignmentRecord,
    ApplicationResult,
    CustomerManagedPolicyReference,
    EntitlementCreationResult,
    Inventory,
    MappingReportRow,
    PermissionSetRecord,
    RoleCreationResult,
)


_NAME_ALPHABET = string.ascii_letters + string.digits + "-_"


@st.composite
def account_id(draw) -> str:
    return draw(st.from_regex(r"\A[0-9]{12}\Z"))


@st.composite
def permission_set_arn(draw) -> str:
    instance = draw(
        st.text(
            min_size=8,
            max_size=20,
            alphabet=string.ascii_lowercase + string.digits,
        )
    )
    ps_id = draw(
        st.text(
            min_size=8,
            max_size=20,
            alphabet=string.ascii_lowercase + string.digits,
        )
    )
    return f"arn:aws:sso:::permissionSet/ssoins-{instance}/ps-{ps_id}"


@st.composite
def principal_id(draw) -> str:
    return draw(st.uuids().map(str))


@st.composite
def cmp_reference(draw) -> CustomerManagedPolicyReference:
    name = draw(st.text(min_size=1, max_size=40, alphabet=_NAME_ALPHABET))
    path = draw(st.sampled_from(["/", "/foo/", "/a/b/c/", "/team/admin/"]))
    return CustomerManagedPolicyReference(name=name, path=path)


@st.composite
def permission_set_record(draw) -> PermissionSetRecord:
    arn = draw(permission_set_arn())
    name = draw(st.text(min_size=1, max_size=32, alphabet=_NAME_ALPHABET))
    description = draw(st.text(max_size=64))
    session_duration = draw(st.sampled_from(["PT1H", "PT4H", "PT8H", "PT12H"]))
    inline_policy = draw(
        st.one_of(
            st.none(),
            st.fixed_dictionaries(
                {
                    "Version": st.just("2012-10-17"),
                    "Statement": st.lists(
                        st.fixed_dictionaries(
                            {
                                "Effect": st.sampled_from(["Allow", "Deny"]),
                                "Action": st.lists(
                                    st.text(min_size=1, max_size=20),
                                    min_size=1,
                                    max_size=3,
                                ),
                                "Resource": st.just("*"),
                            }
                        ),
                        min_size=1,
                        max_size=3,
                    ),
                }
            ),
        )
    )
    aws_managed = draw(
        st.lists(
            st.text(min_size=1, max_size=40, alphabet=_NAME_ALPHABET).map(
                lambda n: f"arn:aws:iam::aws:policy/{n}"
            ),
            max_size=3,
            unique=True,
        )
    )
    cmp_refs = draw(st.lists(cmp_reference(), max_size=3, unique_by=lambda r: (r.name, r.path)))
    permission_boundary = draw(
        st.one_of(
            st.none(),
            st.fixed_dictionaries(
                {
                    "PolicyType": st.just("MANAGED"),
                    "ManagedPolicyArn": st.text(min_size=1, max_size=40).map(
                        lambda n: f"arn:aws:iam::aws:policy/{n}"
                    ),
                }
            ),
        )
    )
    return PermissionSetRecord(
        arn=arn,
        name=name,
        description=description,
        session_duration=session_duration,
        inline_policy=inline_policy,
        aws_managed_policy_arns=tuple(aws_managed),
        customer_managed_policy_references=tuple(cmp_refs),
        permission_boundary=permission_boundary,
    )


@st.composite
def account_assignment_record(draw, ps_arns: list[str]) -> AccountAssignmentRecord:
    ps_arn = draw(st.sampled_from(ps_arns))
    acct = draw(account_id())
    p_type = draw(st.sampled_from(["USER", "GROUP"]))
    p_id = draw(principal_id())
    display = draw(st.text(min_size=1, max_size=20, alphabet=string.ascii_letters))
    return AccountAssignmentRecord(
        permission_set_arn=ps_arn,
        account_id=acct,
        principal_type=p_type,
        principal_id=p_id,
        principal_display_name=display,
    )


@st.composite
def inventory(draw, *, min_ps: int = 1, max_ps: int = 4, max_assignments: int = 6) -> Inventory:
    permission_sets = draw(
        st.lists(
            permission_set_record(),
            min_size=min_ps,
            max_size=max_ps,
            unique_by=lambda ps: ps.arn,
        )
    )
    ps_arns = [ps.arn for ps in permission_sets]
    assignments = draw(
        st.lists(
            account_assignment_record(ps_arns),
            max_size=max_assignments,
        )
    )
    hub = draw(account_id())
    return Inventory(
        hub_account_id=hub,
        idc_instance_arn=f"arn:aws:sso:::instance/ssoins-{hub[:8]}",
        identity_store_id=f"d-{hub[:10]}",
        permission_sets=tuple(permission_sets),
        assignments=tuple(assignments),
        run_id="00000000000000000000000000000000",
        captured_at="2025-01-01T00:00:00+00:00",
    )


@st.composite
def role_creation_result(draw) -> RoleCreationResult:
    status = draw(st.sampled_from(["CREATED", "EXISTING", "SKIPPED", "FAILED"]))
    acct = draw(account_id())
    name = draw(st.text(min_size=1, max_size=32, alphabet=_NAME_ALPHABET))
    arn = None if status == "FAILED" else f"arn:aws:iam::{acct}:role/{name}"
    return RoleCreationResult(
        permission_set_arn=draw(permission_set_arn()),
        account_id=acct,
        role_name=name,
        role_arn=arn,
        status=status,
        error_detail="boom" if status == "FAILED" else "",
    )


@st.composite
def entitlement_creation_result(draw) -> EntitlementCreationResult:
    status = draw(st.sampled_from(["CREATED", "EXISTING", "SKIPPED", "FAILED"]))
    return EntitlementCreationResult(
        application_arn="arn:aws:account-access:us-east-1:111111111111:application/app-x",
        permission_set_arn=draw(permission_set_arn()),
        account_id=draw(account_id()),
        principal_type=draw(st.sampled_from(["USER", "GROUP"])),
        principal_id=draw(principal_id()),
        role_arn=None if status in ("SKIPPED", "FAILED") else "arn:aws:iam::111:role/x",
        entitlement_id=None if status in ("SKIPPED", "FAILED") else "ent-1234567890abcdef",
        status=status,
    )
