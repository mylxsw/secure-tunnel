package main

import (
	"context"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/mylxsw/asteria/level"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/asteria/writer"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/glacier/starter/application"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"github.com/mylxsw/secure-tunnel/internal/tunnel"
	"time"
)

var Version = "1.0"
var GitCommit = "5dbef13fb456f51a5d29464d"
var DEBUG = "false"

func main() {
	//log.All().LogFormatter(formatter.NewJSONFormatter())

	log.All().WithFileLine(DEBUG == "true")

	app := application.Create(fmt.Sprintf("%s %s", Version, GitCommit)).WithShutdownTimeoutFlagSupport()

	app.AddStringFlag("conf", "client.yaml", "服务器配置文件")
	app.Singleton(func(c infra.FlagContext) (*config.Client, error) {
		conf, err := config.LoadClientConfFromFile(c.String("conf"))
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
