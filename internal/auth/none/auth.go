package none

import (
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/secure-tunnel/internal/auth"
)

type Auth struct {
	logger log.Logger
}

func New() auth.Author {
	return &Auth{logger: log.Module("auth:none")}
}

func (provider *Auth) GetUser(username string) (*auth.AuthedUser, error) {
	return &auth.AuthedUser{
		Account: username,
	}, nil
}

func (provider *Auth) Login(username, password string) (*auth.AuthedUser, error) {
	return &auth.AuthedUser{
		Account: username,
	}, nil
}

func (provider *Auth) Users() ([]auth.AuthedUser, error) {
	return []auth.AuthedUser{}, nil
}
