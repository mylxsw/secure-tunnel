package hub

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/mylxsw/secure-tunnel/internal/auth"
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
	tunnel *Tunnel

	linksLock sync.RWMutex // protect links
	links     map[uint16]*Link

	OnCtrlFilter func(cmd Command) bool
	OnDataFilter func(isResp bool, link *Link, data []byte)
}

func NewHub(tunnel *Tunnel) *Hub {
	return &Hub{
		tunnel: tunnel,
		links:  make(map[uint16]*Link),
	}
}

func (h *Hub) TunnelName() string {
	return h.tunnel.String()
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
	if err := h.tunnel.WritePacket(id, data); err != nil {
		log.Errorf("link(%d) write to %s failed:%s", id, h.tunnel, err.Error())
		return false
	}
	return true
}

func (h *Hub) onCtrl(cmd Command) {
	if cmd.Cmd != TunHeartbeat {
		log.Debugf("link(%d) recv cmd:%d", cmd.ID, cmd.Cmd)
	}

	if h.OnCtrlFilter != nil && h.OnCtrlFilter(cmd) {
		return
	}

	id := cmd.ID
	l := h.GetLink(id)
	if l == nil {
		log.Errorf("link(%d) recv Cmd:%d, no Link", id, cmd.Cmd)
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
		log.Errorf("link(%d) receive unknown Cmd:%v", id, cmd)
	}
}

func (h *Hub) onData(id uint16, data []byte) {
	link := h.GetLink(id)
	if link == nil {
		mPool.Put(data)
		log.Errorf("link(%d) no Link", id)
		return
	}

	if h.OnDataFilter != nil {
		h.OnDataFilter(false, link, data)
	}

	if !link.write(data) {
		mPool.Put(data)
		log.Errorf("link(%d) put data failed", id)
	}
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

	// tunnel disconnect, so reset all Link
	h.ResetAllLink()
	log.Warningf("hub(%s) quit", h.tunnel)
}

func (h *Hub) Close() {
	_ = h.tunnel.Close()
}

func (h *Hub) Status() {
	h.linksLock.RLock()
	defer h.linksLock.RUnlock()
	var links []uint16
	for id := range h.links {
		links = append(links, id)
	}
	log.Warningf("<status> %s, %d links(%v)", h.tunnel, len(h.links), links)
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
	log.Infof("link(%d) delete", id)
	h.linksLock.Lock()
	defer h.linksLock.Unlock()
	delete(h.links, id)
}

func (h *Hub) CreateLink(id uint16) *Link {
	log.Infof("link(%d) new Link over %s", id, h.tunnel)
	h.linksLock.Lock()
	defer h.linksLock.Unlock()
	if _, ok := h.links[id]; ok {
		log.Errorf("link(%d) repeated over %s", id, h.tunnel)
		return nil
	}
	l := newLink(id)
	h.links[id] = l
	return l
}

func (h *Hub) StartLink(link *Link, conn *net.TCPConn, authedUser *auth.AuthedUser) {
	_ = conn.SetKeepAlive(true)
	_ = conn.SetKeepAlivePeriod(time.Second * 60)
	link.setConn(conn)

	log.With(authedUser).Infof("link(%d) start %v", link.ID, conn.RemoteAddr())
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
	log.Infof("link(%d) close", link.ID)
}
