package config

import (
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/glacier/infra"
)

type Provider struct{}

func (pro Provider) Register(binder infra.Binder) {
	binder.MustSingletonOverride(func(conf *Config) *LDAP { return &conf.LDAP })
	binder.MustSingletonOverride(func(conf *Config) *Users { return &conf.Users })
}

func (pro Provider) Boot(resolver infra.Resolver) {
	resolver.MustResolve(func(conf *Config) {
		log.With(conf).Debugf("boot configuration")
	})
}
