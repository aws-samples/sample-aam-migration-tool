
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





get all assignments and permission set details
- generate a csv/excel that contains all this information
- excel should contain group/user, permission set name, default role name we want to create, trust policy for default role, policies attached to permission set

then generates cloudformation/terraform with the default roles (including the trust policy and policies required)
- user is given option to modify role name either for each role or all of the roles (either can re-define the default role path or the full name of the role)

- there should be an option to run this in a single account or the entire org, the default should be a single account. We should have a disclaimer for the org run that they may get throttled

