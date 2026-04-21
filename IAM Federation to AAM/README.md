

### Part 2: IAM Federation → AAM (Sowjanya)

For customers using SAML-based IAM federation who want to consolidate into AAM's entitlement model.

The tool handles:

- Discovering federated roles and inheritance chains across accounts
- Identifying undocumented roles via CloudTrail `AssumeRoleWithSAML` analysis
- Updating trust policies for AAM integration
- Creating entitlements in AAM from existing role-to-user group mappings
- Auditing entitlement state post-migration


