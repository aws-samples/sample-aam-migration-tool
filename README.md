# Account Access Manager Migration Tool

A migration tool that helps customers move to Account Access Manager (AAM) from AWS IAM Identity Center (IdC) or IAM Federation. It automates discovery, policy mapping, entitlement creation, and validation to minimize manual effort and reduce risk during the transition.

## Supported Migration Paths

### Part 1: IdC → AAM (Omar)

For customers currently using IdC for account access who need to move to AAM due to quota limits (permission sets, accounts + apps), high permission-set-per-account scenarios (e.g., EKS), or upcoming AAM-only features.

The tool handles:

- Inventorying permission sets and policies via IdC APIs (`GetInlinePolicyForPermissionSet`, `ListCustomerManagedPolicyReferencesInPermissionSet`, `ListAccountAssignments`)
- Extracting entitlement mappings and role-to-permission relationships (Omar)
    - output should contain all the policies associated, inline policy JSON, and entitlement (need to store for all roles)
- Re-creating IAM roles with equivalent permission set policies (Omar)
    - add flag for customer to tag the role or place in a role path to prevent modification
    - or add general tags/metadata (name, tag, etc.)
    - permission boundary, CMPs, AWS Managed, inline policies
- Identifying resource-based policies (RCP/SCP/Resource policies/VPCe) that may need updates
- Logging migration events for auditability

### Part 2: IAM Federation → AAM (Sowjanya)

For customers using SAML-based IAM federation who want to consolidate into AAM's entitlement model.

The tool handles:

- Discovering federated roles and inheritance chains across accounts
- Identifying undocumented roles via CloudTrail `AssumeRoleWithSAML` analysis
- Updating trust policies for AAM integration
- Creating entitlements in AAM from existing role-to-user group mappings
- Auditing entitlement state post-migration

### Path 3: Utilities
- resource/org policy analysis (Blake)
- CloudTrail undocumented roles for AssumeRoleWithSAML (Sowjanya has a script that does some of this)
- SCP creation / immutability support aka adding tags to roles (guidance not technical implementation)

## Migration Workflow

Both paths follow a phased approach:

1. **Discovery** — inventory existing roles, permission sets, policies, and entitlements
2. **Configuration** — create equivalent IAM roles / entitlements in AAM; identify break-glass scenarios
3. **Validation** — test access across a subset of groups; log and audit migration actions
4. **Parallel operations** — run both systems side-by-side until cutover criteria are met
5. **Decommissioning** — disable legacy access after confirming full migration

## Responsibility Model

| Area | Owner |
|---|---|
| Migration tooling, backend config, policy updates, logging infrastructure | AWS |
| Testing, validation, business logic, operational continuity | Customer |
| Role discovery, decommissioning sign-off | Shared |

## Key Considerations

- **Emergency access**: Set up break-glass procedures (IAM users or direct IAM federation) before starting any migration
- **Phased rollout**: Migrate accounts incrementally; maintain a rollback plan
- **Identity source**: Ensure SCIM provisioning and sync with your external IdP (Okta/Entra ID) remain intact
- **IdC quotas**: Default 500 permission sets; 20 TPS collective API throttle — valid migration drivers if you're hitting these
- **Policy mapping**: Customer managed policies must exist in each target account with the same name and path


## TBDs

- IAM Federation

- IdC
- - allow users to specify a role path for new roles
- - naming convention/role path for a group of roles (groupa-admin or groupa/admin)

