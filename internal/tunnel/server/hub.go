package server

import (
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/common"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/hub"
	"net"
)

type Hub struct {
	*hub.Hub
	backend    *Backend
	authedUser *auth.AuthedUser
}

func newHub(tunnel *hub.Tunnel, backend *Backend, authedUser *auth.AuthedUser) *Hub {
	h := &Hub{
		Hub:        hub.NewHub(tunnel),
		backend:    backend,
		authedUser: authedUser,
	}
	h.Hub.OnCtrlFilter = buildCtrlFilter(h)
	h.Hub.OnDataFilter = buildDataFilter(backend, authedUser)
	return h
}

func (h *Hub) handleLink(l *hub.Link) {
	defer common.ErrorHandler()
	defer h.DeleteLink(l.ID)

	conn, err := net.DialTCP("tcp", nil, h.backend.Addr)
	if err != nil {
		log.Errorf("link(%d) connect to serverAddr failed, err:%v", l.ID, err)
		h.SendCommand(l.ID, hub.LinkClose)
		h.DeleteLink(l.ID)
		return
	}

	h.StartLink(l, conn, h.authedUser)
}
