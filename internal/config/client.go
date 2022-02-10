package config

import (
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/mylxsw/go-utils/file"
	"gopkg.in/yaml.v3"
)

type Client struct {
	Verbose  bool                 `json:"verbose" yaml:"verbose"`
	Server   string               `json:"server" yaml:"server"`
	Secret   string               `json:"secret" yaml:"secret"`
	Backends []BackendPortMapping `json:"backends" yaml:"backends"`
	Username string               `json:"username" yaml:"username"`
	Password string               `json:"-" yaml:"password"`
	Tunnels  uint                 `json:"tunnels" yaml:"tunnels"`
	LogPath  string               `json:"log_path" yaml:"log_path"`
}

type BackendPortMapping struct {
	Backend string `json:"backend" yaml:"backend"`
	Listen  string `json:"listen" yaml:"listen"`
}

// populateDefault 填充默认值
func (conf Client) populateDefault() Client {
	if conf.Tunnels == 0 {
		conf.Tunnels = 1
	}

	if conf.Server == "" {
		conf.Server = "127.0.0.1:8080"
	}

	return conf
}

// validate 配置合法性检查
func (conf Client) validate() error {

	return nil
}

// LoadClientConfFromFile 从配置文件加载配置
func LoadClientConfFromFile(configPath string) (*Client, error) {
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

	var conf Client
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, err
	}

	conf = conf.populateDefault()
	if err := conf.validate(); err != nil {
		return nil, err
	}

	return &conf, nil
}
