
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

