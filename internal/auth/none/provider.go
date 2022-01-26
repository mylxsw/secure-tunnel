package none

import (
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/go-utils/str"
	"github.com/mylxsw/secure-tunnel/internal/config"
)

type Provider struct{}

func (p Provider) Register(cc infra.Binder) {
	cc.MustSingletonOverride(New)
}

func (p Provider) ShouldLoad(conf *config.Config) bool {
	return str.InIgnoreCase(conf.AuthType, []string{"none"})
}
