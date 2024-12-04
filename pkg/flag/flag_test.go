package flag_test

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft/tunnel-aws/pkg/flag"
	tunnelflag "github.com/khulnasoft/tunnel/pkg/flag"
)

func TestFlag_ToOptions(t *testing.T) {
	t.Cleanup(viper.Reset)

	group := flag.NewCloudFlagGroup()
	flags := flag.Flags{
		BaseFlags: tunnelflag.Flags{
			GlobalFlagGroup: tunnelflag.NewGlobalFlagGroup(),
		},
		CloudFlagGroup: group,
	}

	viper.Set(tunnelflag.DebugFlag.ConfigName, true)
	viper.Set(tunnelflag.ConfigFileFlag.ConfigName, "test.yaml")
	viper.Set(tunnelflag.CacheDirFlag.ConfigName, "./cache")

	viper.Set(group.MaxCacheAge.ConfigName, "48h")
	viper.Set(group.UpdateCache.ConfigName, true)

	opts, err := flags.ToOptions(nil)
	require.NoError(t, err)

	expected := flag.Options{
		Options: tunnelflag.Options{
			GlobalOptions: tunnelflag.GlobalOptions{
				Debug:      true,
				ConfigFile: "test.yaml",
				CacheDir:   "./cache",
			},
			AppVersion: "dev",
		},
		CloudOptions: flag.CloudOptions{
			MaxCacheAge: time.Duration(48) * time.Hour,
			UpdateCache: true,
		},
	}

	assert.Equal(t, expected, opts)
}

func TestCloudFlagGroup_ToOptions(t *testing.T) {
	t.Cleanup(viper.Reset)

	group := flag.NewCloudFlagGroup()
	viper.Set(group.MaxCacheAge.ConfigName, "48h")
	viper.Set(group.UpdateCache.ConfigName, true)

	opts, err := group.ToOptions()
	require.NoError(t, err)

	expected := flag.CloudOptions{
		MaxCacheAge: time.Duration(48) * time.Hour,
		UpdateCache: true,
	}

	assert.Equal(t, expected, opts)
}
