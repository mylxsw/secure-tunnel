package config

import (
	"github.com/mylxsw/glacier/infra"
)

type ServerProvider struct{}

func (pro ServerProvider) Register(binder infra.Binder) {
	binder.MustSingletonOverride(func(conf *Server) *LDAP { return &conf.LDAP })
	binder.MustSingletonOverride(func(conf *Server) *Users { return &conf.Users })
}
