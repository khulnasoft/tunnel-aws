package neptune

import (
	api "github.com/aws/aws-sdk-go-v2/service/neptune"
	neptuneTypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"

	"github.com/khulnasoft/tunnel-aws/internal/adapters/cloud/aws"
	"github.com/khulnasoft/tunnel-aws/pkg/concurrency"
	"github.com/khulnasoft/tunnel-aws/pkg/types"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/neptune"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

type adapter struct {
	*aws.RootAdapter
	api *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "neptune"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Neptune.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getClusters() ([]neptune.Cluster, error) {

	a.Tracker().SetServiceLabel("Discovering clusters...")

	var apiClusters []neptuneTypes.DBCluster
	var input api.DescribeDBClustersInput
	for {
		output, err := a.api.DescribeDBClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiClusters = append(apiClusters, output.DBClusters...)
		a.Tracker().SetTotalResources(len(apiClusters))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting clusters...")
	return concurrency.Adapt(apiClusters, a.RootAdapter, a.adaptCluster), nil
}

func (a *adapter) adaptCluster(apiCluster neptuneTypes.DBCluster) (*neptune.Cluster, error) {

	metadata := a.CreateMetadataFromARN(*apiCluster.DBClusterArn)

	var auditLogging bool
	for _, export := range apiCluster.EnabledCloudwatchLogsExports {
		if export == "audit" {
			auditLogging = true
			break
		}
	}

	return &neptune.Cluster{
		Metadata: metadata,
		Logging: neptune.Logging{
			Metadata: metadata,
			Audit:    tunnelTypes.Bool(auditLogging, metadata),
		},
		StorageEncrypted: types.ToBool(apiCluster.StorageEncrypted, metadata),
		KMSKeyID:         types.ToString(apiCluster.KmsKeyId, metadata),
	}, nil
}
