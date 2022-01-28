package tunnel

import (
	"context"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"sync"
)

type ClientProvider struct{}

func (p ClientProvider) Register(app infra.Binder) {
}

func (p ClientProvider) Daemon(ctx context.Context, app infra.Resolver) {
	app.MustResolve(func(conf *config.Client) {
		var wg sync.WaitGroup
		wg.Add(len(conf.Backends))
		for _, backend := range conf.Backends {
			go func(backend config.BackendPortMapping) {
				defer wg.Done()

				client, err := NewClient(conf.Server, conf.Secret, backend, conf.Tunnels, conf)
				if err != nil {
					log.With(backend).Errorf("create client failed: %v", err)
					return
				}

				if err := client.Start(ctx); err != nil {
					log.With(backend).Errorf("client started failed: %v", err)
				}
			}(backend)
		}

		wg.Wait()
	})
}

type ServerProvider struct{}

func (p ServerProvider) Register(app infra.Binder) {
	app.MustSingletonOverride(func(conf *config.Server) (*Server, error) {
		return NewServer(conf.Listen, conf.Backends, conf.Secret)
	})
}

func (p ServerProvider) Daemon(ctx context.Context, app infra.Resolver) {
	app.MustResolve(func(server *Server) error {
		return server.Start(ctx, app)
	})
}
