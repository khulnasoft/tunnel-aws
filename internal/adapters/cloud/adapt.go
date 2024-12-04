package cloud

import (
	"context"

	"github.com/khulnasoft/tunnel-aws/internal/adapters/cloud/aws"
	"github.com/khulnasoft/tunnel-aws/internal/adapters/cloud/options"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
)

// Adapt ...
func Adapt(ctx context.Context, opt options.Options) (*state.State, error) {
	cloudState := &state.State{}
	err := aws.Adapt(ctx, cloudState, opt)
	return cloudState, err
}
