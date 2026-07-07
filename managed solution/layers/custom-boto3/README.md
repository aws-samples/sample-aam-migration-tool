# Custom boto3 Lambda Layer

This layer bundles a preview version of boto3/botocore that includes the
`accountaccess` service model (AAM). This is required because the AAM API
is not yet in the public boto3 SDK.

## Building

```bash
cd managed-solution/layers/custom-boto3
./build.sh
```

This installs the `.whl` files from the repo root into `python/`, which CDK
then packages as a Lambda Layer.

## When to remove

Once the `accountaccess` service is available in the standard boto3 SDK
(shipped with the Lambda runtime), this layer can be removed and the CDK
references to it deleted.
