package local

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/mylxsw/secure-tunnel/internal/config"

	"github.com/mylxsw/asteria/log"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	logger log.Logger
	conf   *config.Users
	users  map[string]config.LocalUser
}

func New(conf *config.Users) auth.Author {
	users := make(map[string]config.LocalUser)
	for _, user := range conf.Local {
		users[user.Account] = user
	}

	return &Auth{logger: log.Module("auth:local"), conf: conf, users: users}
}

func (provider *Auth) GetUser(username string) (*auth.AuthedUser, error) {
	if user, ok := provider.users[username]; ok {
		return &auth.AuthedUser{
			UUID:    buildUserID(user.Account, user.Name, "local"),
			Type:    "local",
			Account: user.Account,
			Name:    user.Name,
			Status:  1,
			Groups:  user.GetUserGroups(),
		}, nil
	}

	return nil, auth.ErrNoSuchUser
}

func buildUserID(account string, name string, typ string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s-%s-%s", account, name, typ))))
}

func (provider *Auth) Login(username, password string) (*auth.AuthedUser, error) {

	if user, ok := provider.users[username]; ok {
		switch user.Algo {
		case "base64":
			savedPassword, err := base64.StdEncoding.DecodeString(user.Password)
			if err != nil {
				return nil, auth.ErrInvalidPassword
			}
			if string(savedPassword) != password {
				return nil, auth.ErrInvalidPassword
			}
		case "bcrypt":
			if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
				return nil, auth.ErrInvalidPassword
			}
		default:
			if user.Password != password {
				return nil, auth.ErrInvalidPassword
			}
		}

		return &auth.AuthedUser{
			UUID:    buildUserID(user.Account, user.Name, "local"),
			Type:    "local",
			Account: user.Account,
			Name:    user.Name,
			Groups:  user.GetUserGroups(),
			Status:  1,
		}, nil
	}

	return nil, auth.ErrNoSuchUser
}

func (provider *Auth) Users() ([]auth.AuthedUser, error) {
	users := make([]auth.AuthedUser, 0)
	for _, u := range provider.users {
		users = append(users, auth.AuthedUser{
			UUID:    buildUserID(u.Account, u.Name, "local"),
			Type:    "local",
			Account: u.Account,
			Name:    u.Name,
			Status:  1,
			Groups:  u.GetUserGroups(),
		})
	}

	return users, nil
}
