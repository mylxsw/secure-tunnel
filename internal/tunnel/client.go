//
//   date  : 2014-07-16
//   author: xjdrew
//

package tunnel

import (
	"container/heap"
	"errors"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"net"
	"sync"
	"time"
)

// ClientHub manages client links
type ClientHub struct {
	*Hub
	sent     uint16
	received uint16
}

func (h *ClientHub) heartbeat() {
	heartbeat := getHeartbeat()
	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()

	maxSpan := int(getTimeout() / heartbeat)
	if maxSpan <= tunnelMinSpan {
		maxSpan = tunnelMinSpan
	}

	if log.DebugEnabled() {
		log.Debugf("maxspan: %d", maxSpan)
	}

	for range ticker.C {
		// id overflow
		span := 0xffff - h.received + h.sent + 1
		if int(span) >= maxSpan {
			log.Errorf("tunnel(%v) timeout, sent:%d, received:%d", h.Hub.tunnel, h.sent, h.received)
			h.Hub.Close()
			break
		}

		h.sent = h.sent + 1
		if !h.sendCommand(h.sent, TunHeartbeat) {
			break
		}
	}
}

func (h *ClientHub) onCtrl(cmd Command) bool {
	id := cmd.id
	switch cmd.cmd {
	case TunHeartbeat:
		h.received = id
		return true
	}
	return false
}

func newClientHub(tunnel *Tunnel) *ClientHub {
	h := &ClientHub{
		Hub: newHub(tunnel),
	}
	h.Hub.onCtrlFilter = h.onCtrl
	go h.heartbeat()
	return h
}

// Client tunnel client
type Client struct {
	conf *config.Client

	backend    config.BackendPortMapping
	serverAddr string
	secret     string
	tunnels    uint

	alloc *IDAllocator
	cq    HubQueue
	lock  sync.Mutex
}

func (cli *Client) createHub() (hub *HubItem, err error) {
	conn, err := dial(cli.serverAddr)
	if err != nil {
		return
	}

	tunnel := newTunnel(conn)
	_, challenge, err := tunnel.ReadPacket()
	if err != nil {
		log.Errorf("read challenge failed(%v):%s", tunnel, err)
		return
	}

	a := newEncryptAlgorithm(cli.secret)
	token, ok := a.ExchangeCipherBlock(challenge)
	if !ok {
		err = errors.New("exchange challenge failed")
		log.Errorf("exchange challenge failed(%v)", tunnel)
		return
	}

	if err = tunnel.WritePacket(0, token); err != nil {
		log.Errorf("write token failed(%v):%s", tunnel, err)
		return
	}

	tunnel.SetCipherKey(a.GetRc4key())

	if err = tunnel.WritePacket(0, buildAuthPacket(cli.conf.Username, cli.conf.Password, cli.backend.Backend)); err != nil {
		log.Errorf("write username & password failed(%v):%s", tunnel, err)
		return
	}

	hub = &HubItem{
		ClientHub: newClientHub(tunnel),
	}
	return
}

func (cli *Client) addHub(item *HubItem) {
	cli.lock.Lock()
	heap.Push(&cli.cq, item)
	cli.lock.Unlock()
}

func (cli *Client) removeHub(item *HubItem) {
	cli.lock.Lock()
	heap.Remove(&cli.cq, item.index)
	cli.lock.Unlock()
}

func (cli *Client) fetchHub() *HubItem {
	defer cli.lock.Unlock()
	cli.lock.Lock()

	if len(cli.cq) == 0 {
		return nil
	}
	item := cli.cq[0]
	item.priority += 1
	heap.Fix(&cli.cq, 0)
	return item
}

func (cli *Client) dropHub(item *HubItem) {
	cli.lock.Lock()
	item.priority -= 1
	heap.Fix(&cli.cq, item.index)
	cli.lock.Unlock()
}

func (cli *Client) handleConnection(hub *HubItem, conn *net.TCPConn) {
	defer exceptionHandler()
	defer cli.dropHub(hub)
	defer func() {
		_ = conn.Close()
	}()

	id := cli.alloc.Acquire()
	defer cli.alloc.Release(id)

	h := hub.Hub
	l := h.createLink(id)
	defer h.deleteLink(id)

	h.sendCommand(id, LinkCreate)
	h.startLink(l, conn, &auth.AuthedUser{Account: cli.conf.Username})
}

func (cli *Client) listen() error {
	ln, err := net.Listen("tcp", cli.backend.Listen)
	if err != nil {
		return err
	}

	defer func() {
		_ = ln.Close()
	}()

	tcpListener := ln.(*net.TCPListener)
	for {
		conn, err := tcpListener.AcceptTCP()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				log.Warningf("accept failed temporary: %s", netErr.Error())
				continue
			} else {
				return err
			}
		}
		log.Infof("new connection from %v", conn.RemoteAddr())
		hub := cli.fetchHub()
		if hub == nil {
			log.Errorf("no active hub")
			_ = conn.Close()
			continue
		}

		_ = conn.SetKeepAlive(true)
		_ = conn.SetKeepAlivePeriod(time.Second * 60)
		go cli.handleConnection(hub, conn)
	}
}

// Start .
func (cli *Client) Start() error {
	sz := cap(cli.cq)
	for i := 0; i < sz; i++ {
		go func(index int) {
			defer exceptionHandler()

			for {
				hub, err := cli.createHub()
				if err != nil {
					log.Errorf("tunnel %d reconnect failed", index)
					time.Sleep(time.Second * 3)
					continue
				}

				log.Errorf("tunnel %d connect succeed", index)
				cli.addHub(hub)
				hub.Start()
				cli.removeHub(hub)
				log.Errorf("tunnel %d disconnected", index)
			}
		}(i)
	}

	return cli.listen()
}

func (cli *Client) Status() {
	defer cli.lock.Unlock()
	cli.lock.Lock()
	for _, hub := range cli.cq {
		hub.Status()
	}
}

func NewClient(serverAddr, secret string, backend config.BackendPortMapping, tunnels uint, conf *config.Client) (*Client, error) {
	client := &Client{
		conf:       conf,
		backend:    backend,
		serverAddr: serverAddr,
		secret:     secret,
		tunnels:    tunnels,
		alloc:      newIDAllocator(),
		cq:         make(HubQueue, tunnels)[0:0],
	}
	return client, nil
}
