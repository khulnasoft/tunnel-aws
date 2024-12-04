package flag

import (
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	tunnelFlag "github.com/khulnasoft/tunnel/pkg/flag"
)

type Flags struct {
	BaseFlags      tunnelFlag.Flags
	CloudFlagGroup *CloudFlagGroup
}

type Options struct {
	tunnelFlag.Options
	CloudOptions
}

func (f *Flags) Bind(cmd *cobra.Command) error {
	err := f.BaseFlags.Bind(cmd)
	if err != nil {
		return xerrors.Errorf("%w", err)
	}

	for _, ff := range f.CloudFlagGroup.Flags() {
		if err := ff.Bind(cmd); err != nil {
			return err
		}
	}

	return nil
}

func (f *Flags) ToOptions(args []string) (Options, error) {
	baseOptions, err := f.BaseFlags.ToOptions(args)
	if err != nil {
		return Options{}, xerrors.Errorf("%w", err)
	}

	opts := Options{
		Options: baseOptions,
	}
	if f.CloudFlagGroup != nil {
		opts.CloudOptions, err = f.CloudFlagGroup.ToOptions()
		if err != nil {
			return Options{}, xerrors.Errorf("cloud flag error: %w", err)
		}
	}

	return opts, nil
}

func (f *Flags) AddFlags(cmd *cobra.Command) {
	f.BaseFlags.AddFlags(cmd)
	for _, flag := range f.CloudFlagGroup.Flags() {
		flag.Add(cmd)
	}
}
