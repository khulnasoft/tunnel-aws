package flag

import (
	"time"

	"golang.org/x/xerrors"

	tunnelflag "github.com/khulnasoft/tunnel/pkg/flag"
)

var (
	cloudUpdateCacheFlag = tunnelflag.Flag[bool]{
		Name:       "update-cache",
		ConfigName: "cloud.update-cache",
		Usage:      "Update the cache for the applicable cloud provider instead of using cached results.",
	}
	cloudMaxCacheAgeFlag = tunnelflag.Flag[time.Duration]{
		Name:       "max-cache-age",
		ConfigName: "cloud.max-cache-age",
		Default:    time.Hour * 24,
		Usage:      "The maximum age of the cloud cache. Cached data will be required from the cloud provider if it is older than this.",
	}
)

type CloudFlagGroup struct {
	UpdateCache *tunnelflag.Flag[bool]
	MaxCacheAge *tunnelflag.Flag[time.Duration]
}

type CloudOptions struct {
	MaxCacheAge time.Duration
	UpdateCache bool
}

func NewCloudFlagGroup() *CloudFlagGroup {
	return &CloudFlagGroup{
		UpdateCache: cloudUpdateCacheFlag.Clone(),
		MaxCacheAge: cloudMaxCacheAgeFlag.Clone(),
	}
}

func (f *CloudFlagGroup) Name() string {
	return "Cloud"
}

func (f *CloudFlagGroup) Flags() []tunnelflag.Flagger {
	return []tunnelflag.Flagger{
		f.UpdateCache,
		f.MaxCacheAge,
	}
}

func (f *CloudFlagGroup) ToOptions() (CloudOptions, error) {
	if err := parseFlags(f); err != nil {
		return CloudOptions{}, err
	}
	return CloudOptions{
		UpdateCache: f.UpdateCache.Value(),
		MaxCacheAge: f.MaxCacheAge.Value(),
	}, nil
}

func parseFlags(fg tunnelflag.FlagGroup) error {
	for _, flag := range fg.Flags() {
		if err := flag.Parse(); err != nil {
			return xerrors.Errorf("unable to parse flag: %w", err)
		}
	}
	return nil
}
