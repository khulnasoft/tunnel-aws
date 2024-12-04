package kms

import (
	api "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/khulnasoft/tunnel-aws/internal/adapters/cloud/aws"
	"github.com/khulnasoft/tunnel-aws/pkg/concurrency"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/kms"
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
	return "kms"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.KMS.Keys, err = a.getKeys()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getKeys() ([]kms.Key, error) {

	a.Tracker().SetServiceLabel("Discovering keys...")

	var apiKeys []types.KeyListEntry
	var input api.ListKeysInput
	for {
		output, err := a.api.ListKeys(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiKeys = append(apiKeys, output.Keys...)
		a.Tracker().SetTotalResources(len(apiKeys))
		if output.NextMarker == nil {
			break
		}
		input.Marker = output.NextMarker
	}

	a.Tracker().SetServiceLabel("Adapting keys...")
	return concurrency.Adapt(apiKeys, a.RootAdapter, a.adaptKey), nil
}

func (a *adapter) adaptKey(apiKey types.KeyListEntry) (*kms.Key, error) {

	metadata := a.CreateMetadataFromARN(*apiKey.KeyArn)

	output, err := a.api.DescribeKey(a.Context(), &api.DescribeKeyInput{
		KeyId: apiKey.KeyId,
	})
	if err != nil {
		return nil, err
	}

	return &kms.Key{
		Metadata:        metadata,
		Usage:           tunnelTypes.String(string(output.KeyMetadata.KeyUsage), metadata),
		RotationEnabled: tunnelTypes.Bool(output.KeyMetadata.ValidTo != nil, metadata),
	}, nil
}
