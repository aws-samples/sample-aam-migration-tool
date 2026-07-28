## design tenants

- MUST be light-weight (not a large amount of packages or installs to make)
- MUST be fast, assume a variety of users with varying compute power
- MUST looks/feels like an AWS service console (research internally if needed for frameworks to use)
- MUST be ran on a local machine using local resources, not cloud resources
    - cache resources when possible in a local file that is referenced e.g., resource policy analysis, permission set dumps, referenced assignments from idc or their IAM federation configuration that is provided

## features

- separate tabs in the UI to complete different functions
    - policy analysis
        - allow the user to scope the run to a single or multiple accounts (MUST leverage local AWS credential chain with input for what profiles to use)
        - allow the user to scope based on resource type and region
    - IAM federation to AAM
    - IdC to AAM

### IAM federation to AAM
    - user MUST provide the input entitlements/assignments for the account(s) they are migrating
        - these are then viewable in the front-end
    - user selects from a list of the federated roles which ones to "migrate", migration involves updating the trust policy of the roles by just adding the necessary sts:assumerole call with the AAM service principal
    - on completion of migration (no errors from AWS SDK), update a local file with a success. If it fails, update the file with a failure indicating what resource (IAM role) failed.


### IdC to AAM
    - should have a note indicating the user MUST supply a credential profile for the IdC management or delegated admin account
    - Once profile is supplied, this will run the analysis and dump all permission sets and assignments in a neat format that they can select from
    - user will select from the list of permission sets and assignments they want to migrate. These should be organized by account
    - This will generate a cloudformation template with roles to create