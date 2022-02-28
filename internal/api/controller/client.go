package controller

import (
	"fmt"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/glacier/web"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"net/http"
	"strings"
)

type ClientController struct {
	resolver infra.Resolver
}

func NewClientController(resolver infra.Resolver) web.Controller {
	return &ClientController{
		resolver: resolver,
	}
}

func (c ClientController) Register(router web.Router) {
	router.Group("/client", func(router web.Router) {
		router.Get("/config/{secret}", c.GenerateConf)
	})
}

type ClientConfResp struct {
	ServerPort string                      `json:"server_port"`
	Backends   []config.BackendPortMapping `json:"backends"`
	Secret     string                      `json:"secret"`
}

func (c ClientController) GenerateConf(ctx web.Context, conf *config.Server) web.Response {
	secret := ctx.PathVar("secret")
	if secret != conf.Secret {
		return ctx.JSONError(fmt.Sprintf("invalid secert"), http.StatusBadRequest)
	}

	backends := make([]config.BackendPortMapping, 0)
	for _, back := range conf.Backends {
		listenAddr := back.BindSuggest
		if listenAddr == "" {
			listenAddr = fmt.Sprintf("127.0.0.1:%s", strings.Split(back.Addr, ":")[1])
		}

		backends = append(backends, config.BackendPortMapping{
			Backend: back.Name,
			Listen:  listenAddr,
		})
	}

	return ctx.JSON(ClientConfResp{
		Backends:   backends,
		ServerPort: strings.Split(conf.Listen, ":")[1],
		Secret:     secret,
	})
}
