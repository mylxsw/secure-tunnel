package client

import (
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/hub"
	"time"
)

const (
	TunnelMinSpan = 3               // 3次心跳无回应则断开
	Heartbeat     = 1 * time.Second // Heartbeat interval for tunnel heartbeat
	Timeout       = time.Duration(0) * time.Second
)

// Hub manages client links
type Hub struct {
	*hub.Hub
	sent     uint16
	received uint16
}

func (h *Hub) heartbeat() {
	ticker := time.NewTicker(Heartbeat)
	defer ticker.Stop()

	maxSpan := int(Timeout / Heartbeat)
	if maxSpan <= TunnelMinSpan {
		maxSpan = TunnelMinSpan
	}

	for range ticker.C {
		// ID overflow
		span := 0xffff - h.received + h.sent + 1
		if int(span) >= maxSpan {
			log.F(log.M{
				"span":     span,
				"max_span": maxSpan,
			}).Errorf("%s timeout, sent:%d, received:%d", h.Hub.TunnelName(), h.sent, h.received)
			h.Hub.Close()
			break
		}

		h.sent = h.sent + 1
		if !h.SendCommand(h.sent, hub.TunHeartbeat) {
			break
		}
	}
}

func (h *Hub) onCtrl(cmd hub.Command) bool {
	id := cmd.ID
	switch cmd.Cmd {
	case hub.TunHeartbeat:
		h.received = id
		return true
	}
	return false
}

func newClientHub(tun *hub.Tunnel) *Hub {
	h := &Hub{
		Hub: hub.NewHub(tun),
	}
	h.Hub.OnCtrlFilter = h.onCtrl
	go h.heartbeat()
	return h
}
