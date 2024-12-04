# tunnel-aws

## Installing Tunnel AWS Plugin

```shell
$ tunnel plugin install github.com/khulnasoft/tunnel-aws
```

## Usage

Scan an AWS account for misconfigurations. Tunnel uses the same authentication methods as the AWS CLI. See https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html

The following services are supported:

- accessanalyzer
- api-gateway
- athena
- cloudfront
- cloudtrail
- cloudwatch
- codebuild
- documentdb
- dynamodb
- ec2
- ecr
- ecs
- efs
- eks
- elasticache
- elasticsearch
- elb
- emr
- iam
- kinesis
- kms
- lambda
- mq
- msk
- neptune
- rds
- redshift
- s3
- sns
- sqs
- ssm
- workspaces

```shell
Usage:
  tunnel aws [flags]

Examples:
  # basic scanning
  $ tunnel aws --region us-east-1

  # limit scan to a single service:
  $ tunnel aws --region us-east-1 --service s3

  # limit scan to multiple services:
  $ tunnel aws --region us-east-1 --service s3 --service ec2

  # force refresh of cache for fresh results
  $ tunnel aws --region us-east-1 --update-cache
```

Please see [ARCHITECTURE.md](ARCHITECTURE.md) for more information.

_tunnel-aws_ is an [KhulnaSoft Security](https://khulnasoft.com) open source project.
Learn about our open source work and portfolio [here](https://www.khulnasoft.com/products/open-source-projects/).
Join the community, and talk to us about any matter in [GitHub Discussion](https://github.com/khulnasoft/tunnel/discussions).
