package config

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"

	"github.com/mylxsw/go-utils/file"
	"github.com/mylxsw/go-utils/str"
)

type Config struct {
	Verbose  bool   `json:"verbose" yaml:"verbose,omitempty"`
	AuthType string `json:"auth_type" yaml:"auth_type"`
	LogPath  string `json:"log_path" yaml:"log_path"`

	LDAP  LDAP  `json:"ldap" yaml:"ldap,omitempty"`
	Users Users `json:"users,omitempty" yaml:"users,omitempty"`
}

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

// LoadConfFromFile 从配置文件加载配置
func LoadConfFromFile(configPath string) (*Config, error) {
	if configPath == "" {
		return nil, errors.New("config file path is required")
	}

	if !file.Exist(configPath) {
		return nil, fmt.Errorf("config file %s not exist", configPath)
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var conf Config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, err
	}

	conf = conf.populateDefault()
	if err := conf.validate(); err != nil {
		return nil, err
	}

	return &conf, nil
}

// populateDefault 填充默认值
func (conf Config) populateDefault() Config {
	if conf.AuthType == "" {
		conf.AuthType = "misc"
	}

	if conf.LDAP.DisplayName == "" {
		conf.LDAP.DisplayName = "displayName"
	}

	if conf.LDAP.UID == "" {
		conf.LDAP.UID = "sAMAccountName"
	}

	if conf.LDAP.UserFilter == "" {
		conf.LDAP.UserFilter = "CN=all-staff,CN=Users,DC=example,DC=com"
	}

	return conf
}

// validate 配置合法性检查
func (conf Config) validate() error {
	if !str.In(conf.AuthType, []string{"misc", "ldap", "local"}) {
		return fmt.Errorf("invalid auth_type: must be one of misc|local|ldap")
	}

	return nil
}
