package hub

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/common"
	"net"
	"sync"
	"time"

	"github.com/mylxsw/asteria/log"
)

var ErrPeerClosed = errors.New("ErrPeerClosed")

const (
	LinkData uint8 = iota
	LinkCreate
	LinkClose
	LinkCloseRecv
	LinkCloseSend
	TunHeartbeat
)

type Command struct {
	Cmd uint8  // control command
	ID  uint16 // ID
}

type Hub struct {
	Tunnel *Tunnel

	linksLock sync.RWMutex // protect links
	links     map[uint16]*Link

	OnCtrlFilter func(cmd Command) bool
	OnDataFilter func(isResp bool, link *Link, data []byte)
}

func NewHub(tunnel *Tunnel) *Hub {
	return &Hub{
		Tunnel: tunnel,
		links:  make(map[uint16]*Link),
	}
}

func (h *Hub) SendCommand(id uint16, cmd uint8) bool {
	buf := bytes.NewBuffer(mPool.Get()[0:0])
	c := Command{
		Cmd: cmd,
		ID:  id,
	}
	_ = binary.Write(buf, binary.LittleEndian, &c)

	return h.send(0, buf.Bytes())
}

func (h *Hub) send(id uint16, data []byte) bool {
	if err := h.Tunnel.WritePacket(id, data); err != nil {
		log.Errorf("Link(%d) write to %s failed:%s", id, h.Tunnel, err.Error())
		return false
	}
	return true
}

func (h *Hub) onCtrl(cmd Command) {
	if cmd.Cmd != TunHeartbeat {
		log.Debugf("Link(%d) recv cmd:%d", cmd.ID, cmd.Cmd)
	}

	if h.OnCtrlFilter != nil && h.OnCtrlFilter(cmd) {
		return
	}

	id := cmd.ID
	l := h.GetLink(id)
	if l == nil {
		log.Errorf("Link(%d) recv Cmd:%d, no Link", id, cmd.Cmd)
		return
	}

	switch cmd.Cmd {
	case LinkClose:
		l.close()
	case LinkCloseRecv:
		l.closeRead()
	case LinkCloseSend:
		l.closeWrite()
	default:
		log.Errorf("Link(%d) receive unknown Cmd:%v", id, cmd)
	}
}

func (h *Hub) onData(id uint16, data []byte) {
	link := h.GetLink(id)
	if link == nil {
		mPool.Put(data)
		log.Errorf("Link(%d) no Link", id)
		return
	}

	if h.OnDataFilter != nil {
		h.OnDataFilter(false, link, data)
	}

	if !link.write(data) {
		mPool.Put(data)
		log.Errorf("Link(%d) put data failed", id)
	}
}

func (h *Hub) Start() {
	defer func() { _ = h.Tunnel.Close() }()

	for {
		id, data, err := h.Tunnel.ReadPacket()
		if err != nil {
			log.Errorf("%s read failed:%v", h.Tunnel, err)
			break
		}

		if id == 0 {
			var cmd Command
			buf := bytes.NewBuffer(data)
			err := binary.Read(buf, binary.LittleEndian, &cmd)
			mPool.Put(data)
			if err != nil {
				log.Errorf("parse message failed:%s, break dispatch", err.Error())
				break
			}
			h.onCtrl(cmd)
		} else {
			h.onData(id, data)
		}
	}

	// Tunnel disconnect, so reset all Link
	h.ResetAllLink()
	log.Warningf("hub(%s) quit", h.Tunnel)
}

func (h *Hub) Close() {
	_ = h.Tunnel.Close()
}

func (h *Hub) Status() {
	h.linksLock.RLock()
	defer h.linksLock.RUnlock()
	var links []uint16
	for id := range h.links {
		links = append(links, id)
	}
	log.Warningf("<status> %s, %d links(%v)", h.Tunnel, len(h.links), links)
}

func (h *Hub) ResetAllLink() {
	h.linksLock.RLock()
	defer h.linksLock.RUnlock()

	log.Errorf("reset all %d links", len(h.links))
	for _, l := range h.links {
		l.close()
	}
}

// GetLink hub function
func (h *Hub) GetLink(id uint16) *Link {
	h.linksLock.RLock()
	defer h.linksLock.RUnlock()
	return h.links[id]
}

func (h *Hub) DeleteLink(id uint16) {
	log.Infof("Link(%d) delete", id)
	h.linksLock.Lock()
	defer h.linksLock.Unlock()
	delete(h.links, id)
}

func (h *Hub) CreateLink(id uint16) *Link {
	log.Infof("Link(%d) new Link over %s", id, h.Tunnel)
	h.linksLock.Lock()
	defer h.linksLock.Unlock()
	if _, ok := h.links[id]; ok {
		log.Errorf("Link(%d) repeated over %s", id, h.Tunnel)
		return nil
	}
	l := &Link{
		ID:          id,
		writeBuffer: common.NewBuffer(16),
	}
	h.links[id] = l
	return l
}

func (h *Hub) StartLink(link *Link, conn *net.TCPConn, authedUser *auth.AuthedUser) {
	_ = conn.SetKeepAlive(true)
	_ = conn.SetKeepAlivePeriod(time.Second * 60)
	link.setConn(conn)

	log.With(authedUser).Infof("Link(%d) start %v", link.ID, conn.RemoteAddr())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = link.conn.CloseRead() }()

		for {
			data, err := link.read()
			if err != nil {
				if err != ErrPeerClosed {
					h.SendCommand(link.ID, LinkCloseSend)
				}
				break
			}

			if h.OnDataFilter != nil {
				h.OnDataFilter(true, link, data)
			}

			h.send(link.ID, data)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = link.conn.CloseWrite() }()

		err := link._write()
		if err != ErrPeerClosed {
			h.SendCommand(link.ID, LinkCloseRecv)
		}
	}()
	wg.Wait()
	log.Infof("Link(%d) close", link.ID)
}
