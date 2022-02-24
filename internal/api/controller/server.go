package controller

import (
	"github.com/mylxsw/coll"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/glacier/web"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/server"
	"time"
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

type UserConnections struct {
	User        *auth.AuthedUser `json:"user"`
	Connections []Connection     `json:"connections"`
}

type Connection struct {
	ID         string    `json:"id"`
	Backend    string    `json:"backend"`
	LocalAddr  string    `json:"local_addr"`
	RemoteAddr string    `json:"remote_addr"`
	ReadBytes  int64     `json:"read_bytes"`
	WriteBytes int64     `json:"write_bytes"`
	CreatedAt  time.Time `json:"created_at"`
}

func (ctl ServerController) ServerStatus(wtx web.Context, srv *server.Server) web.Response {
	connections := coll.MustNew(srv.Status()).
		GroupBy(func(cs server.ConnStatus) string { return cs.User.UUID }).
		Map(func(css []interface{}, uuid interface{}) UserConnections {
			conns := make([]Connection, 0)
			for _, v := range css {
				cs := v.(server.ConnStatus)
				conns = append(conns, Connection{
					ID:         cs.ID,
					Backend:    cs.Backend,
					LocalAddr:  cs.LocalAddr,
					RemoteAddr: cs.RemoteAddr,
					ReadBytes:  cs.ReadBytes,
					WriteBytes: cs.WriteBytes,
					CreatedAt:  cs.CreatedAt,
				})
			}

			return UserConnections{Connections: conns, User: css[0].(server.ConnStatus).User}
		}).AsArray().Items()

	return wtx.JSON(web.M{"data": connections})
}
