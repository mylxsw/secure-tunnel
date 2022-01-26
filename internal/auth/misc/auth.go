package misc

import (
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/mylxsw/secure-tunnel/internal/auth/ldap"
	"github.com/mylxsw/secure-tunnel/internal/auth/local"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"strings"
)

type Auth struct {
	logger    log.Logger
	ldapAuth  auth.Author
	localAuth auth.Author
}

func New(ldapConf *config.LDAP, localConf *config.Users) auth.Author {
	return &Auth{logger: log.Module("auth:misc"), ldapAuth: ldap.New(ldapConf, localConf), localAuth: local.New(localConf)}
}

func (provider *Auth) GetUser(username string) (*auth.AuthedUser, error) {
	if strings.HasPrefix(username, "local:") {
		return provider.localAuth.GetUser(strings.TrimPrefix(username, "local:"))
	}

	if strings.HasPrefix(username, "ldap:") {
		return provider.ldapAuth.GetUser(strings.TrimPrefix(username, "ldap:"))
	}

	rs, err := provider.localAuth.GetUser(username)
	if err != nil {
		return provider.ldapAuth.GetUser(username)
	}

	return rs, nil
}

func (provider *Auth) Login(username, password string) (*auth.AuthedUser, error) {
	if strings.HasPrefix(username, "local:") {
		return provider.localAuth.Login(strings.TrimPrefix(username, "local:"), password)
	}

	if strings.HasPrefix(username, "ldap:") {
		return provider.ldapAuth.Login(strings.TrimPrefix(username, "ldap:"), password)
	}

	rs, err := provider.localAuth.Login(username, password)
	if err != nil {
		return provider.ldapAuth.Login(username, password)
	}

	return rs, nil
}

func (provider *Auth) Users() ([]auth.AuthedUser, error) {
	localUsers, _ := provider.localAuth.Users()
	ldapUsers, _ := provider.ldapAuth.Users()

	localUsers = append(localUsers, ldapUsers...)
	return localUsers, nil
}
