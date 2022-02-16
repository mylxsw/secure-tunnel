package controller

import (
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/glacier/web"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/server"
)

type ServerController struct {
	resolver infra.Resolver
}

func NewServerController(resolver infra.Resolver) web.Controller {
	return &ServerController{resolver: resolver}
}

func (ctl ServerController) Register(router web.Router) {
	router.Group("/server", func(router web.Router) {
		router.Get("/status", ctl.ServerStatus)
	})
}

func (ctl ServerController) ServerStatus(wtx web.Context, server *server.Server) web.Response {
	return wtx.JSON(web.M{"connections": server.Status()})
}
