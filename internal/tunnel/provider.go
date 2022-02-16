package tunnel

import (
	"context"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/graceful"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/client"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/server"
	"sync"
)

type ClientProvider struct{}

func (p ClientProvider) Register(app infra.Binder) {
}

func (p ClientProvider) Daemon(ctx context.Context, app infra.Resolver) {
	app.MustResolve(func(conf *config.Client, gf graceful.Graceful) {
		var wg sync.WaitGroup
		wg.Add(len(conf.Backends))
		for _, backend := range conf.Backends {
			go func(backend config.BackendPortMapping) {
				defer wg.Done()

				clientServer, err := client.NewClient(conf.Server, conf.Secret, backend, conf.Tunnels, conf)
				if err != nil {
					log.With(backend).Errorf("create client failed: %v", err)
					return
				}

				if err := clientServer.Start(ctx, gf); err != nil {
					log.With(backend).Errorf("client started failed: %v", err)
				}
			}(backend)
		}

		wg.Wait()
	})
}

type ServerProvider struct{}

func (p ServerProvider) Register(app infra.Binder) {
	app.MustSingletonOverride(func(conf *config.Server) (*server.Server, error) {
		return server.NewServer(conf.Listen, conf.Backends, conf.Secret)
	})
}

func (p ServerProvider) Daemon(ctx context.Context, app infra.Resolver) {
	app.MustResolve(func(server *server.Server) error {
		return server.Start(ctx, app)
	})
}
