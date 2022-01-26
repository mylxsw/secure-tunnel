package auth

import (
	"errors"
)

type Author interface {
	Login(username, password string) (*AuthedUser, error)
	GetUser(username string) (*AuthedUser, error)
	Users() ([]AuthedUser, error)
}

type AuthedUser struct {
	Type    string   `json:"type" yaml:"type"`
	UUID    string   `json:"uuid" yaml:"uuid"`
	Name    string   `json:"name" yaml:"name"`
	Account string   `json:"account" yaml:"account"`
	Groups  []string `json:"groups" yaml:"groups"`
	Status  int8     `json:"status" yaml:"status"`
}

var ErrNoSuchUser = errors.New("user not found")
var ErrInvalidPassword = errors.New("invalid password")
