//
//   date  : 2014-06-05
//   author: xjdrew
//

package tunnel

import (
	"bytes"
	"encoding/binary"
	"github.com/mylxsw/asteria/log"
	"sync"
)

const (
	LinkData uint8 = iota
	LinkCreate
	LinkClose
	LinkCloseRecv
	LinkCloseSend
	TunHeartbeat
)

type Command struct {
	cmd uint8  // control command
	id  uint16 // id
}

type Hub struct {
	tunnel *Tunnel

	ll    sync.RWMutex // protect links
	links map[uint16]*Link

	onCtrlFilter func(cmd Command) bool
}

func (h *Hub) sendCommand(id uint16, cmd uint8) bool {
	buf := bytes.NewBuffer(mpool.Get()[0:0])
	c := Command{
		cmd: cmd,
		id:  id,
	}
	_ = binary.Write(buf, binary.LittleEndian, &c)

	if cmd == TunHeartbeat {
		log.Debugf("%s send heartbeat: %d", h.tunnel, id)
	} else {
		log.Infof("Link(%d) send cmd:%d", id, cmd)
	}

	return h.send(0, buf.Bytes())
}

func (h *Hub) send(id uint16, data []byte) bool {
	if err := h.tunnel.WritePacket(id, data); err != nil {
		log.Errorf("Link(%d) write to %s failed:%s", id, h.tunnel, err.Error())
		return false
	}
	return true
}

func (h *Hub) onCtrl(cmd Command) {
	if cmd.cmd == TunHeartbeat {
		log.Debugf("%s recv heartbeat: %d", h.tunnel, cmd.id)
	} else {
		log.Infof("Link(%d) recv cmd:%d", cmd.id, cmd.cmd)
	}

	if h.onCtrlFilter != nil && h.onCtrlFilter(cmd) {
		return
	}

	id := cmd.id
	l := h.getLink(id)
	if l == nil {
		log.Errorf("Link(%d) recv cmd:%d, no Link", id, cmd.cmd)
		return
	}

	switch cmd.cmd {
	case LinkClose:
		l.close()
	case LinkCloseRecv:
		l.closeRead()
	case LinkCloseSend:
		l.closeWrite()
	default:
		log.Errorf("Link(%d) receive unknown cmd:%v", id, cmd)
	}
}

func (h *Hub) onData(id uint16, data []byte) {
	log.Infof("Link(%d) recv %d bytes data", id, len(data))

	link := h.getLink(id)
	if link == nil {
		mpool.Put(data)
		log.Errorf("Link(%d) no Link", id)
		return
	}

	if !link.write(data) {
		mpool.Put(data)
		log.Errorf("Link(%d) put data failed", id)
		return
	}
	return
}

func (h *Hub) Start() {
	defer func() { _ = h.tunnel.Close() }()

	for {
		id, data, err := h.tunnel.ReadPacket()
		if err != nil {
			log.Errorf("%s read failed:%v", h.tunnel, err)
			break
		}

		if id == 0 {
			var cmd Command
			buf := bytes.NewBuffer(data)
			err := binary.Read(buf, binary.LittleEndian, &cmd)
			mpool.Put(data)
			if err != nil {
				log.Errorf("parse message failed:%s, break dispatch", err.Error())
				break
			}
			h.onCtrl(cmd)
		} else {
			h.onData(id, data)
		}
	}

	// tunnel disconnect, so reset all Link
	h.resetAllLink()
	log.Warningf("hub(%s) quit", h.tunnel)
}

func (h *Hub) Close() {
	_ = h.tunnel.Close()
}

func (h *Hub) Status() {
	h.ll.RLock()
	defer h.ll.RUnlock()
	var links []uint16
	for id := range h.links {
		links = append(links, id)
	}
	log.Warningf("<status> %s, %d links(%v)", h.tunnel, len(h.links), links)
}

func (h *Hub) resetAllLink() {
	h.ll.RLock()
	defer h.ll.RUnlock()

	log.Errorf("reset all %d links", len(h.links))
	for _, l := range h.links {
		l.close()
	}
}

func newHub(tunnel *Tunnel) *Hub {
	return &Hub{
		tunnel: tunnel,
		links:  make(map[uint16]*Link),
	}
}
