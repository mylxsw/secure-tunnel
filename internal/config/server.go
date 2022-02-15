package config

import (
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/mylxsw/go-utils/file"
	"github.com/mylxsw/go-utils/str"
	"gopkg.in/yaml.v3"
)

// LoadServerConfFromFile 从配置文件加载配置
func LoadServerConfFromFile(configPath string) (*Server, error) {
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

	var conf Server
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, err
	}

	conf = conf.populateDefault()
	if err := conf.validate(); err != nil {
		return nil, err
	}

	return &conf, nil
}

type Server struct {
	HTTPListen string          `json:"http_listen" yaml:"http_listen"`
	Listen     string          `json:"listen" yaml:"listen"`
	Backends   []BackendServer `json:"backends" yaml:"backends"`
	Secret     string          `json:"-" yaml:"secret"`

	Verbose  bool   `json:"verbose" yaml:"verbose,omitempty"`
	AuthType string `json:"auth_type" yaml:"auth_type"`
	LogPath  string `json:"log_path" yaml:"log_path"`

	LDAP  LDAP  `json:"ldap" yaml:"ldap,omitempty"`
	Users Users `json:"users,omitempty" yaml:"users,omitempty"`
}

type BackendServer struct {
	Addr        string `json:"addr" yaml:"addr"`
	Name        string `json:"name" yaml:"name"`
	Protocol    string `json:"protocol" yaml:"protocol"`
	LogResponse bool   `json:"-" yaml:"log_response"`
}

// populateDefault 填充默认值
func (conf Server) populateDefault() Server {
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

	for i, back := range conf.Backends {
		if back.Name == "" {
			back.Name = back.Addr
		}

		if back.Protocol == "" {
			back.Protocol = "tcp"
		}

		conf.Backends[i] = back
	}

	return conf
}

// validate 配置合法性检查
func (conf Server) validate() error {
	if !str.In(conf.AuthType, []string{"misc", "ldap", "local"}) {
		return fmt.Errorf("invalid auth_type: must be one of misc|local|ldap")
	}

	for i, user := range conf.Users.Local {
		if user.Account == "" {
			return fmt.Errorf("invalid users.local[%d], account is required", i)
		}
	}

	return nil
}
