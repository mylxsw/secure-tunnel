package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/mylxsw/go-utils/file"
	"github.com/mylxsw/secure-tunnel/internal/api/controller"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/mylxsw/asteria/level"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/asteria/writer"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/glacier/starter/application"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"github.com/mylxsw/secure-tunnel/internal/tunnel"
)

var Version = "1.0"
var GitCommit = "5dbef13fb456f51a5d29464d"

func main() {
	app := application.Create(fmt.Sprintf("%s %s", Version, GitCommit)).WithShutdownTimeoutFlagSupport(1 * time.Second)

	app.AddStringFlag("conf", buildDefaultConfigPath(), "服务器配置文件")
	app.AddStringFlag("server", "", "server address")
	app.AddStringFlag("secret", "", "server secret")
	app.AddIntFlag("tunnels", 0, "tunnels")

	app.Singleton(func(c infra.FlagContext) (*config.Client, error) {
		confPath := c.String("conf")
		ensureConfigFile(confPath)

		conf, err := config.LoadClientConfFromFile(confPath)
		if err != nil {
			return conf, err
		}

		if conf.Username == "" {
			if err := survey.AskOne(&survey.Input{Message: "Please type your username"}, &conf.Username); err != nil {
				panic(fmt.Errorf("invalid username: %v", err))
			}
		}

		if conf.Password == "" {
			if err := survey.AskOne(&survey.Password{Message: "Please type your password"}, &conf.Password); err != nil {
				panic(fmt.Errorf("invalid password: %v", err))
			}
		}

		if conf.Username == "" || conf.Password == "" {
			panic(fmt.Errorf("username and password are required"))
		}

		if c.String("server") != "" {
			conf.Server = c.String("server")
		}

		if c.String("secret") != "" {
			conf.Secret = c.String("secret")
		}

		if c.Int("tunnels") != 0 {
			conf.Tunnels = uint(c.Int("tunnels"))
		}

		return conf, err
	})

	app.AfterInitialized(func(resolver infra.Resolver) error {
		return resolver.Resolve(func(conf *config.Client) {
			if conf.LogPath != "" {
				log.All().LogWriter(writer.NewDefaultRotatingFileWriter(context.TODO(), func(le level.Level, module string) string {
					return fmt.Sprintf(conf.LogPath, fmt.Sprintf("%s-%s", le.GetLevelName(), time.Now().Format("20060102")))
				}))
			}
		})
	})

	app.Provider(tunnel.ClientProvider{})

	application.MustRun(app)
}

func buildDefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "client.yaml"
	}

	return filepath.Join(home, "secure-tunnel.client.yaml")
}

func ensureConfigFile(defaultConfigFile string) string {
	if !file.Exist(defaultConfigFile) {
		log.Errorf("配置文件不存在，请录入以下信息自动生成: %s", defaultConfigFile)

		var serverAddress string
		if err := survey.AskOne(&survey.Input{Message: "Please input server address", Default: "http://127.0.0.1:8081/api/client/config/Zc4z-n1dd-6qu"}, &serverAddress); err != nil {
			panic(fmt.Errorf("invalid server address: %v", err))
		}

		clientConfData, err := yaml.Marshal(requestServer(serverAddress))
		if err != nil {
			panic(err)
		}

		if err := ioutil.WriteFile(defaultConfigFile, clientConfData, os.ModePerm); err != nil {
			panic(fmt.Errorf("create config file failed: %v", err))
		}
	}

	return defaultConfigFile
}

func requestServer(serverAddress string) config.Client {
	serverURL, err := url.Parse(serverAddress)
	if err != nil {
		panic(fmt.Errorf("invalid server address: %v", err))
	}

	resp, err := http.Get(serverAddress)
	if err != nil {
		panic(fmt.Errorf("request to server failed: %v", err))
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Errorf("read response body from server failed: %v", err))
	}

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Errorf("server response invalid code: %s", string(data)))
	}

	var clientConfResp controller.ClientConfResp
	if err := json.Unmarshal(data, &clientConfResp); err != nil {
		panic(fmt.Errorf("unmarshal response body failed: %v", err))
	}

	client := config.Client{}
	client.Server = fmt.Sprintf("%s:%s", serverURL.Hostname(), clientConfResp.ServerPort)
	client.Backends = clientConfResp.Backends
	client.Secret = clientConfResp.Secret

	return client
}
