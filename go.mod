module github.com/khulnasoft/tunnel-aws

go 1.20

require (
	github.com/aws/aws-sdk-go v1.47.12
	github.com/aws/aws-sdk-go-v2 v1.23.1
	github.com/aws/aws-sdk-go-v2/config v1.25.1
	github.com/aws/aws-sdk-go-v2/credentials v1.16.1
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.23.2
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.20.2
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.17.2
	github.com/aws/aws-sdk-go-v2/service/athena v1.35.1
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.30.2
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.33.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.30.2
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.27.1
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.25.2
	github.com/aws/aws-sdk-go-v2/service/docdb v1.27.2
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.25.2
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.134.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.22.2
	github.com/aws/aws-sdk-go-v2/service/ecs v1.33.1
	github.com/aws/aws-sdk-go-v2/service/efs v1.23.2
	github.com/aws/aws-sdk-go-v2/service/eks v1.33.1
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.32.2
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.24.2
	github.com/aws/aws-sdk-go-v2/service/elasticsearchservice v1.23.2
	github.com/aws/aws-sdk-go-v2/service/emr v1.33.1
	github.com/aws/aws-sdk-go-v2/service/iam v1.27.2
	github.com/aws/aws-sdk-go-v2/service/kafka v1.26.2
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.22.2
	github.com/aws/aws-sdk-go-v2/service/kms v1.26.2
	github.com/aws/aws-sdk-go-v2/service/lambda v1.47.0
	github.com/aws/aws-sdk-go-v2/service/mq v1.19.2
	github.com/aws/aws-sdk-go-v2/service/neptune v1.26.2
	github.com/aws/aws-sdk-go-v2/service/rds v1.62.4
	github.com/aws/aws-sdk-go-v2/service/redshift v1.36.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.42.2
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.23.2
	github.com/aws/aws-sdk-go-v2/service/sns v1.25.2
	github.com/aws/aws-sdk-go-v2/service/sqs v1.28.1
	github.com/aws/aws-sdk-go-v2/service/sts v1.25.2
	github.com/aws/aws-sdk-go-v2/service/workspaces v1.33.2
	github.com/khulnasoft/defsec v1.0.3
	github.com/khulnasoft/go-mock-aws v0.0.0-20231122183358-438e2fa97a36
	github.com/khulnasoft/tunnel-iac v0.0.1
	github.com/liamg/iamgo v0.0.9
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.8.4
)

require (
	dario.cat/mergo v1.0.0 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/ProtonMail/go-crypto v0.0.0-20230717121422-5aa5874ade95 // indirect
	github.com/acomagu/bufpipe v1.0.4 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/agnivade/levenshtein v1.1.1 // indirect
	github.com/alecthomas/chroma v0.10.0 // indirect
	github.com/apparentlymart/go-textseg/v13 v13.0.0 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/aquasecurity/defsec v0.93.2-0.20231117234854-a13ada52a90f // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.14.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.2.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.5.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.7.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.2.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.10.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.2.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.10.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.16.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.17.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.19.2 // indirect
	github.com/aws/smithy-go v1.17.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cloudflare/circl v1.3.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dlclark/regexp2 v1.4.0 // indirect
	github.com/docker/distribution v2.8.2+incompatible // indirect
	github.com/docker/docker v24.0.7+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.4.1 // indirect
	github.com/go-git/go-git/v5 v5.8.1 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/hashicorp/hcl/v2 v2.18.1 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/khulnasoft/tunnel-policies v0.0.1 // indirect
	github.com/liamg/jfather v0.0.7 // indirect
	github.com/liamg/memoryfs v1.6.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/open-policy-agent/opa v0.57.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0-rc5 // indirect
	github.com/owenrumney/squealer v1.2.1 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.16.0 // indirect
	github.com/prometheus/client_model v0.4.0 // indirect
	github.com/prometheus/common v0.44.0 // indirect
	github.com/prometheus/procfs v0.10.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20200313005456-10cdbea86bc0 // indirect
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/skeema/knownhosts v1.2.0 // indirect
	github.com/tchap/go-patricia/v2 v2.3.1 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	github.com/zclconf/go-cty v1.13.0 // indirect
	go.opentelemetry.io/otel v1.16.0 // indirect
	go.opentelemetry.io/otel/metric v1.16.0 // indirect
	go.opentelemetry.io/otel/sdk v1.16.0 // indirect
	go.opentelemetry.io/otel/trace v1.16.0 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/mod v0.10.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	golang.org/x/tools v0.8.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)
