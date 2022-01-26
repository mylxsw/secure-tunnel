package misc

import (
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/go-utils/str"
	"github.com/mylxsw/secure-tunnel/internal/config"
)

type Provider struct{}

func (p Provider) Register(cc infra.Binder) {
	cc.MustSingletonOverride(New)
	log.Debugf("provider internal.auth.misc loaded")
}

func (p Provider) ShouldLoad(config *config.Config) bool {
	return str.InIgnoreCase(config.AuthType, []string{"misc"})
}
