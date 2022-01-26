package main

import (
	"context"
	"fmt"
	"github.com/mylxsw/asteria/level"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/asteria/writer"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/glacier/starter/application"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"time"
)

var Version = "1.0"
var GitCommit = "5dbef13fb456f51a5d29464d"

func main() {
	//log.All().LogFormatter(formatter.NewJSONFormatter())

	app := application.Create(fmt.Sprintf("%s %s", Version, GitCommit))

	app.AddStringFlag("conf", "client.yaml", "服务器配置文件")
	app.Singleton(func(c infra.FlagContext) (*config.Config, error) {
		return config.LoadConfFromFile(c.String("conf"))
	})

	app.AfterInitialized(func(resolver infra.Resolver) error {
		return resolver.Resolve(func(conf *config.Config) {
			if conf.LogPath != "" {
				log.All().LogWriter(writer.NewDefaultRotatingFileWriter(context.TODO(), func(le level.Level, module string) string {
					return fmt.Sprintf(conf.LogPath, fmt.Sprintf("%s-%s", le.GetLevelName(), time.Now().Format("20060102")))
				}))
			}
		})
	})

	app.Provider(
		config.Provider{},
	)

	application.MustRun(app)
}
