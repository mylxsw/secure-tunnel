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
	h.Hub.OnCtrlFilter = h.onCtrlFilter
	h.Hub.OnDataFilter = h.buildDataFilter(backend, authedUser)
	return h
}

func (h *Hub) handleLink(l *hub.Link) {
	defer common.ErrorHandler()
	defer h.DeleteLink(l.ID)

	conn, err := net.DialTCP("tcp", nil, h.backend.Addr)
	if err != nil {
		log.With(h.authedUser).Errorf("link(%d) connect to %s failed: %v", l.ID, h.backend.Addr, err)
		h.SendCommand(l.ID, hub.LinkClose)
		h.DeleteLink(l.ID)
		return
	}

	h.StartLink(l, conn, h.authedUser)
}

func (h *Hub) onCtrlFilter(cmd hub.Command) bool {
	id := cmd.ID
	switch cmd.Cmd {
	case hub.LinkCreate:
		l := h.CreateLink(id)
		if l != nil {
			go h.handleLink(l)
		} else {
			h.SendCommand(id, hub.LinkClose)
		}
		return true
	case hub.TunHeartbeat:
		h.SendCommand(id, hub.TunHeartbeat)
		return true
	}
	return false
}

func (h *Hub) buildDataFilter(backend *Backend, authedUser *auth.AuthedUser) func(isResp bool, link *hub.Link, data []byte) {
	return func(isResp bool, link *hub.Link, data []byte) {
		if backend.Backend.Protocol == "" || isResp {
			return
		}

		switch backend.Backend.Protocol {
		case "redis":
			go redisProtocolFilter(link, data, authedUser, backend)
		case "mysql":
			go mysqlProtocolFilter(link, data, authedUser, backend)
		case "mongo":
			go mongoProtocolFilter(link, data, authedUser, backend)
		default:
			go defaultProtocolFilter(link, data, authedUser, backend)
		}
	}
}
