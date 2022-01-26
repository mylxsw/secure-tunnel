package ldap

import (
	"errors"
	"fmt"
	"github.com/mylxsw/go-utils/str"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"time"

	lp "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/mylxsw/asteria/log"
)

type Auth struct {
	conf     *config.LDAP
	userConf *config.Users
	users    map[string]config.LDAPUser
	logger   log.Logger
}

func New(conf *config.LDAP, userConfig *config.Users) auth.Author {
	users := make(map[string]config.LDAPUser)
	for _, u := range userConfig.LDAP {
		users[u.Account] = u
	}

	return &Auth{conf: conf, userConf: userConfig, logger: log.Module("auth:ldap"), users: users}
}

func (provider *Auth) GetUser(username string) (*auth.AuthedUser, error) {
	return provider.getUser(username, nil)
}

func (provider *Auth) getUser(username string, cb func(l *lp.Conn, user *auth.AuthedUser, entry *lp.Entry) error) (*auth.AuthedUser, error) {
	log.WithFields(log.Fields{"username": username}).Debugf("ldap get user")

	res, err := provider.getConnection(func(l *lp.Conn) (interface{}, error) {
		searchReq := lp.NewSearchRequest(
			provider.conf.BaseDN,
			lp.ScopeWholeSubtree,
			lp.NeverDerefAliases,
			0,
			0,
			false,
			fmt.Sprintf("(&(objectClass=organizationalPerson)(%s=%s))", provider.conf.UID, lp.EscapeFilter(username)),
			[]string{"objectguid", provider.conf.UID, provider.conf.DisplayName, "userAccountControl", "memberOf"},
			nil,
		)

		sr, err := l.Search(searchReq)
		if err != nil {
			return nil, fmt.Errorf("LDAP 用户查询失败: %w", err)
		}

		if len(sr.Entries) != 1 {
			return nil, fmt.Errorf("用户不存在")
		}

		// 514-禁用 512-启用
		if sr.Entries[0].GetAttributeValue("userAccountControl") == "514" {
			return nil, errors.New("LDAP 用户账户已禁用")
		}

		authedUser := provider.buildAuthedUserFromLDAPEntry(sr.Entries[0])

		if cb != nil {
			if err := cb(l, &authedUser, sr.Entries[0]); err != nil {
				return nil, err
			}
		}

		return &authedUser, nil
	})
	if err != nil {
		return nil, err
	}

	return res.(*auth.AuthedUser), nil
}

func (provider *Auth) getConnection(cb func(l *lp.Conn) (interface{}, error)) (interface{}, error) {
	l, err := lp.DialURL(provider.conf.URL)
	if err != nil {
		return nil, fmt.Errorf("无法连接 LDAP 服务器: %w", err)
	}
	defer l.Close()

	l.SetTimeout(5 * time.Second)
	if err := l.Bind(provider.conf.Username, provider.conf.Password); err != nil {
		return nil, fmt.Errorf("LDAP 服务器鉴权失败: %w", err)
	}

	return cb(l)
}

func (provider *Auth) Login(username, password string) (*auth.AuthedUser, error) {
	return provider.getUser(username, func(l *lp.Conn, user *auth.AuthedUser, entry *lp.Entry) error {
		return l.Bind(entry.DN, password)
	})
}

func (provider *Auth) buildAuthedUserFromLDAPEntry(entry *lp.Entry) auth.AuthedUser {
	userStatus := 1
	if entry.GetAttributeValue("userAccountControl") == "514" {
		userStatus = 0
	}

	authedUser := auth.AuthedUser{
		Type:    "ldap",
		UUID:    uuid.Must(uuid.FromBytes(entry.GetRawAttributeValue("objectGUID"))).String(),
		Name:    entry.GetAttributeValue(provider.conf.DisplayName),
		Account: entry.DN,
		Groups:  entry.GetAttributeValues("memberOf"),
		Status:  int8(userStatus),
	}

	if user, ok := provider.users[entry.DN]; ok {
		authedUser.Groups = str.Distinct(append(authedUser.Groups, user.GetUserGroups()...))
	}

	return authedUser
}

func (provider *Auth) Users() ([]auth.AuthedUser, error) {
	res, err := provider.getConnection(func(l *lp.Conn) (interface{}, error) {
		searchReq := lp.NewSearchRequest(
			provider.conf.BaseDN,
			lp.ScopeWholeSubtree,
			lp.NeverDerefAliases,
			0,
			0,
			false,
			fmt.Sprintf("(&(objectClass=organizationalPerson)(memberOf=%s))", lp.EscapeFilter(provider.conf.UserFilter)),
			[]string{"objectguid", provider.conf.UID, provider.conf.DisplayName, "userAccountControl", "memberOf"},
			nil,
		)

		sr, err := l.Search(searchReq)
		if err != nil {
			return nil, fmt.Errorf("LDAP 用户查询失败: %w", err)
		}

		authedUsers := make([]auth.AuthedUser, 0)
		for _, ent := range sr.Entries {
			if ent.GetAttributeValue("userAccountControl") == "514" {
				continue
			}

			authedUsers = append(authedUsers, provider.buildAuthedUserFromLDAPEntry(ent))
		}

		return authedUsers, nil
	})

	if err != nil {
		return nil, err
	}

	return res.([]auth.AuthedUser), nil
}
