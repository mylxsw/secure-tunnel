package client

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/graceful"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/common"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/hub"
	"net"
	"sync"
	"time"
)

const (
	TunnelMinSpan = 3 // 3次心跳无回应则断开
)

// Heartbeat interval for Tunnel heartbeat, seconds.
var Heartbeat int = 1 // seconds

func GetHeartbeat() time.Duration {
	if Heartbeat <= 0 {
		Heartbeat = 1
	}
	return time.Duration(Heartbeat) * time.Second
}

var (
	// Timeout for Tunnel write/read, seconds
	Timeout int = 0 //
)

func GetTimeout() time.Duration {
	return time.Duration(Timeout) * time.Second
}

// Hub manages client links
type Hub struct {
	*hub.Hub
	sent     uint16
	received uint16
}

func (h *Hub) heartbeat() {
	heartbeat := GetHeartbeat()
	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()

	maxSpan := int(GetTimeout() / heartbeat)
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
			}).Errorf("tunnel(%v) timeout, sent:%d, received:%d", h.Hub.Tunnel, h.sent, h.received)
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

// Client tunnel client
type Client struct {
	conf *config.Client

	backend    config.BackendPortMapping
	serverAddr string
	secret     string
	tunnels    uint

	alloc *common.IDAllocator
	cq    Queue
	lock  sync.Mutex
}

func (cli *Client) createHub(gf graceful.Graceful) (hubItem *Item, err error) {
	defer func() {
		if err2 := recover(); err2 != nil {
			err = fmt.Errorf("create client hubItem failed: %v", err2)
			log.Errorf("%v", err)
			gf.Shutdown()
		}
	}()

	conn, err := common.Dial(cli.serverAddr)
	if err != nil {
		panic(fmt.Errorf("dial failed: %v", err))
		return
	}

	tun := hub.NewTunnel(conn)
	_, challenge, err := tun.ReadPacket()
	if err != nil {
		panic(fmt.Errorf("read challenge failed(%v):%s", tun, err))
		return
	}

	a := common.NewEncryptAlgorithm(cli.secret)
	token, ok := a.ExchangeCipherBlock(challenge)
	if !ok {
		err = errors.New("exchange challenge failed")
		panic(fmt.Errorf("exchange challenge failed(%v)", tun))
		return
	}

	if err = tun.WritePacket(0, token); err != nil {
		panic(fmt.Errorf("write token failed(%v):%s", tun, err))
		return
	}

	tun.SetCipherKey(a.GetRc4key())

	if err = tun.WritePacket(0, common.BuildAuthPacket(cli.conf.Username, cli.conf.Password, cli.backend.Backend)); err != nil {
		panic(fmt.Errorf("write username & password failed(%v):%s", tun, err))
		return
	}

	_, authedPacket, err := tun.ReadPacket()
	if err != nil {
		panic(fmt.Errorf("auth failed(%v):%s", tun, err))
		return
	}

	if string(authedPacket) != "ok" {
		panic(fmt.Errorf("auth failed: %s", string(authedPacket)))
	}

	hubItem = &Item{
		Hub: newClientHub(tun),
	}

	return
}

func (cli *Client) addHub(item *Item) {
	cli.lock.Lock()
	heap.Push(&cli.cq, item)
	cli.lock.Unlock()
}

func (cli *Client) removeHub(item *Item) {
	cli.lock.Lock()
	heap.Remove(&cli.cq, item.Index)
	cli.lock.Unlock()
}

func (cli *Client) fetchHub() *Item {
	defer cli.lock.Unlock()
	cli.lock.Lock()

	if len(cli.cq) == 0 {
		return nil
	}
	item := cli.cq[0]
	item.Priority += 1
	heap.Fix(&cli.cq, 0)
	return item
}

func (cli *Client) dropHub(item *Item) {
	cli.lock.Lock()
	item.Priority -= 1
	heap.Fix(&cli.cq, item.Index)
	cli.lock.Unlock()
}

func (cli *Client) handleConnection(item *Item, conn *net.TCPConn) {
	defer common.ErrorHandler()
	defer cli.dropHub(item)
	defer func() {
		_ = conn.Close()
	}()

	id := cli.alloc.Acquire()
	defer cli.alloc.Release(id)

	h := item.Hub
	l := h.CreateLink(id)
	defer h.DeleteLink(id)

	h.SendCommand(id, hub.LinkCreate)
	h.StartLink(l, conn, &auth.AuthedUser{Account: cli.conf.Username})
}

func (cli *Client) listen(ctx context.Context) error {
	ln, err := net.Listen("tcp", cli.backend.Listen)
	if err != nil {
		return err
	}

	defer func() { _ = ln.Close() }()

	tcpListener := ln.(*net.TCPListener)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := tcpListener.AcceptTCP()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					log.Warningf("accept failed temporary: %s", netErr.Error())
					continue
				}
				return err
			}

			log.Infof("new connection from %v", conn.RemoteAddr())

			h := cli.fetchHub()
			if h == nil {
				log.Errorf("no active hub")
				_ = conn.Close()
				continue
			}

			_ = conn.SetKeepAlive(true)
			_ = conn.SetKeepAlivePeriod(time.Second * 60)
			go cli.handleConnection(h, conn)
		}
	}
}

// Start .
func (cli *Client) Start(ctx context.Context, gf graceful.Graceful) error {
	for i := 0; i < cap(cli.cq); i++ {
		go func(index int) {
			defer common.ErrorHandler()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					hub, err := cli.createHub(gf)
					if err != nil {
						log.Errorf("tunnel %d reconnect failed", index)
						time.Sleep(time.Second * 15)
						continue
					}

					func() {
						log.Debugf("tunnel %d connect succeed", index)
						defer func() {
							cli.removeHub(hub)
							log.Warningf("tunnel %d disconnected", index)
						}()

						cli.addHub(hub)
						hub.Start()
					}()
				}
			}
		}(i)
	}

	return cli.listen(ctx)
}

func (cli *Client) Status() {
	defer cli.lock.Unlock()
	cli.lock.Lock()
	for _, h := range cli.cq {
		h.Status()
	}
}

func NewClient(serverAddr, secret string, backend config.BackendPortMapping, tunnels uint, conf *config.Client) (*Client, error) {
	client := &Client{
		conf:       conf,
		backend:    backend,
		serverAddr: serverAddr,
		secret:     secret,
		tunnels:    tunnels,
		alloc:      common.NewIDAllocator(),
		cq:         make(Queue, tunnels)[0:0],
	}
	return client, nil
}
