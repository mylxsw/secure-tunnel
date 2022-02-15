package api

import (
	"fmt"
	"github.com/mylxsw/secure-tunnel/internal/api/controller"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"net"
	"net/http"
	"runtime/debug"

	"github.com/gorilla/mux"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/glacier/listener"
	"github.com/mylxsw/glacier/web"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Provider struct{}

func (s Provider) Aggregates() []infra.Provider {
	return []infra.Provider{
		web.Provider(
			confListenerBuilder{},
			web.SetMuxRouteHandlerOption(s.muxRoutes),
			web.SetRouteHandlerOption(s.routes),
			web.SetExceptionHandlerOption(s.exceptionHandler),
		),
	}
}

func (s Provider) Register(app infra.Binder) {}

func (s Provider) exceptionHandler(ctx web.Context, err interface{}) web.Response {
	log.Errorf("error: %v, call stack: %s", err, debug.Stack())
	return ctx.JSONWithCode(web.M{
		"error": fmt.Sprintf("%v", err),
	}, http.StatusInternalServerError)
}

func (s Provider) routes(resolver infra.Resolver, router web.Router, mw web.RequestMiddleware) {
	mws := make([]web.HandlerDecorator, 0)
	mws = append(mws,
		mw.AccessLog(log.Module("api")),
		mw.CORS("*"),
	)

	router.WithMiddleware(mws...).Controllers(
		"/api",
		controller.NewServerController(resolver),
	)
}

func (s Provider) muxRoutes(cc infra.Resolver, router *mux.Router) {
	cc.MustResolve(func() {
		// prometheus metrics
		router.PathPrefix("/metrics").Handler(promhttp.Handler())
		// health check
		router.PathPrefix("/health").Handler(HealthCheck{})
	})
}

type HealthCheck struct{}

func (h HealthCheck) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Add("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte(`{"status": "UP"}`))
}

type confListenerBuilder struct{}

func (l confListenerBuilder) Build(cc infra.Resolver) (net.Listener, error) {
	return listener.Default(cc.MustGet((*config.Server)(nil)).(*config.Server).HTTPListen).Build(cc)
}
