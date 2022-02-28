package auth

import (
	"errors"
	"github.com/mylxsw/asteria/log"
)

type Author interface {
	Login(username, password string) (*AuthedUser, error)
	GetUser(username string) (*AuthedUser, error)
	Users() ([]AuthedUser, error)
}

type AuthedUser struct {
	Type    string   `json:"type,omitempty" yaml:"type,omitempty"`
	UUID    string   `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	Name    string   `json:"name,omitempty" yaml:"name,omitempty"`
	Account string   `json:"account,omitempty" yaml:"account,omitempty"`
	Groups  []string `json:"groups,omitempty" yaml:"groups,omitempty"`
	Status  int8     `json:"status,omitempty" yaml:"status,omitempty"`
}

func (au *AuthedUser) ToLogEntry() log.M {
	return log.M{
		"type":    au.Type,
		"uuid":    au.UUID,
		"name":    au.Name,
		"account": au.Account,
	}
}

var ErrNoSuchUser = errors.New("user not found")
var ErrInvalidPassword = errors.New("invalid password")
