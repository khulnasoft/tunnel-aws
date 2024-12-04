package types

import (
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func ToString(p *string, m tunnelTypes.Metadata) tunnelTypes.StringValue {
	if p == nil {
		return tunnelTypes.StringDefault("", m)
	}
	return tunnelTypes.String(*p, m)
}

func ToBool(p *bool, m tunnelTypes.Metadata) tunnelTypes.BoolValue {
	if p == nil {
		return tunnelTypes.BoolDefault(false, m)
	}
	return tunnelTypes.Bool(*p, m)
}

func ToInt(p *int32, m tunnelTypes.Metadata) tunnelTypes.IntValue {
	if p == nil {
		return tunnelTypes.IntDefault(0, m)
	}
	return tunnelTypes.IntFromInt32(*p, m)
}
