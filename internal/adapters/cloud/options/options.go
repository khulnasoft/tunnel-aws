package options

import (
	"github.com/khulnasoft/defsec/pkg/debug"

	"github.com/khulnasoft/tunnel-aws/pkg/concurrency"
	"github.com/khulnasoft/tunnel-aws/pkg/progress"
)

type Options struct {
	ProgressTracker     progress.Tracker
	Region              string
	Endpoint            string
	Services            []string
	DebugWriter         debug.Logger
	ConcurrencyStrategy concurrency.Strategy
}
