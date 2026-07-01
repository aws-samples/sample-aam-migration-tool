# TODO: AAM Infrastructure-as-Code coverage

## Status

`generate-iac` mode now emits a single CloudFormation template
(`output/<run_id>/roles.yaml`) containing BOTH:

- `AWS::IAM::Role` resources (one per permission set in the migration plan), and
- `AWS::AccountAccess::Entitlement` resources (one per IdC assignment), wired to
  their role via `Fn::GetAtt <RoleLogicalId>.Arn` and targeting the
  operator-supplied `--aam-application-arn`.

So both roles and entitlements can be deployed as IaC with zero live mutation.

## Still deferred

1. **Terraform output** — removed for now. The Terraform provider/resources for
   the AAM preview service are not yet available. When they ship, add a
   Terraform emitter alongside the CloudFormation one (re-introduce
   `role_to_tf` / a `roles.tf` writer and the `python-hcl2` test dependency).

2. **AWS::AccountAccess::Application** — the AAM application remains an
   operator-managed prerequisite supplied via `--aam-application-arn`. If/when
   it is worth managing the application itself as IaC, add an
   `AWS::AccountAccess::Application` resource and an option to emit it.

3. **Cross-account distribution** — multi-account IaC fan-out (CloudFormation
   StackSets) is still future work; current output targets a single account.

## Reference

- CloudFormation entitlement schema: `AWS::AccountAccess::Entitlement`
  (ApplicationArn + Entitlement.PrincipalRole.{Principal.IdentityCenter.UserId|
  GroupId, RoleArn}); EntitlementId / Account / CreatedAt are read-only.
- Live API request shapes: `entitlement_creator.py`.
- AAM service model: botocore `accountaccess/2018-05-10/service-2.json`.
