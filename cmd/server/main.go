package main

import (
	"context"
	"fmt"
	"github.com/mylxsw/asteria/formatter"
	"github.com/mylxsw/asteria/level"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/asteria/writer"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/glacier/starter/application"
	"github.com/mylxsw/secure-tunnel/internal/auth/ldap"
	"github.com/mylxsw/secure-tunnel/internal/auth/local"
	"github.com/mylxsw/secure-tunnel/internal/auth/misc"
	"github.com/mylxsw/secure-tunnel/internal/auth/none"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"github.com/mylxsw/secure-tunnel/internal/tunnel"
	"time"
)

var Version = "1.0"
var GitCommit = "5dbef13fb456f51a5d29464d"
var DEBUG = "false"

func main() {
	log.All().LogFormatter(formatter.NewJSONFormatter())
	log.All().WithFileLine(DEBUG == "true")

	app := application.Create(fmt.Sprintf("%s %s", Version, GitCommit)).WithShutdownTimeoutFlagSupport()

	app.AddStringFlag("conf", "server.yaml", "服务器配置文件")
	app.Singleton(func(c infra.FlagContext) (*config.Server, error) {
		return config.LoadServerConfFromFile(c.String("conf"))
	})

	app.AfterInitialized(func(resolver infra.Resolver) error {
		return resolver.Resolve(func(conf *config.Server) {
			if conf.LogPath != "" {
				log.All().LogWriter(writer.NewDefaultRotatingFileWriter(context.TODO(), func(le level.Level, module string) string {
					return fmt.Sprintf(conf.LogPath, fmt.Sprintf("%s-%s", le.GetLevelName(), time.Now().Format("20060102")))
				}))
			}
		})
	})

	app.Provider(
		ldap.Provider{},
		none.Provider{},
		local.Provider{},
		misc.Provider{},
		config.ServerProvider{},
		tunnel.ServerProvider{},
	)

	application.MustRun(app)
}
