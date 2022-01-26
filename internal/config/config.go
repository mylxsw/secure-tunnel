package config

import (
	"github.com/mylxsw/go-utils/str"
)

// LDAP 域账号登录配置
type LDAP struct {
	URL         string `json:"url" yaml:"url,omitempty"`
	BaseDN      string `json:"base_dn" yaml:"base_dn,omitempty"`
	Username    string `json:"username" yaml:"username,omitempty"`
	Password    string `json:"-" yaml:"password,omitempty"`
	DisplayName string `json:"display_name" yaml:"display_name,omitempty"`
	UID         string `json:"uid" yaml:"uid,omitempty"`
	UserFilter  string `json:"user_filter" yaml:"user_filter,omitempty"`
}

// Users 用户配置
type Users struct {
	IgnoreAccountSuffix string      `json:"ignore_account_suffix" yaml:"ignore_account_suffix,omitempty"`
	Local               []LocalUser `json:"local,omitempty" yaml:"local,omitempty"`
	LDAP                []LDAPUser  `json:"ldap,omitempty" yaml:"ldap,omitempty"`
}

// LDAPUser ldap 用户配置
type LDAPUser struct {
	Account string   `json:"account" yaml:"account"`
	Group   string   `json:"group,omitempty" yaml:"group,omitempty"`
	Groups  []string `json:"groups,omitempty" yaml:"groups,omitempty"`
}

// GetUserGroups 获取用户所属 groups
func (user LDAPUser) GetUserGroups() []string {
	if user.Groups == nil {
		user.Groups = make([]string, 0)
	}
	if user.Group != "" {
		user.Groups = append(user.Groups, user.Group)
	}

	return str.Distinct(user.Groups)
}

// LocalUser 本地用户配置
type LocalUser struct {
	Name     string   `json:"name" yaml:"name"`
	Account  string   `json:"account" yaml:"account"`
	Password string   `json:"-" yaml:"password"`
	Group    string   `json:"group,omitempty" yaml:"group,omitempty"`
	Groups   []string `json:"groups,omitempty" yaml:"groups,omitempty"`
	Algo     string   `json:"algo" yaml:"algo"`
}

// GetUserGroups 获取用户所属的 groups
func (user LocalUser) GetUserGroups() []string {
	if user.Groups == nil {
		user.Groups = make([]string, 0)
	}
	if user.Group != "" {
		user.Groups = append(user.Groups, user.Group)
	}

	return str.Distinct(user.Groups)
}
