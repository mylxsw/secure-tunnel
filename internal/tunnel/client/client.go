package client

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/common"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/hub"
	"net"
	"sync"
	"time"
)

// Client tunnel client
type Client struct {
	initConnToRemote sync.Once
	conf             *config.Client
	version          string

	backend    config.BackendPortMapping
	serverAddr string
	secret     string
	tunnels    uint

	alloc *idAllocator
	cq    queue
	lock  sync.Mutex
}

func NewClient(version string, serverAddr, secret string, backend config.BackendPortMapping, tunnels uint, conf *config.Client) (*Client, error) {
	client := &Client{
		conf:       conf,
		version:    version,
		backend:    backend,
		serverAddr: serverAddr,
		secret:     secret,
		tunnels:    tunnels,
		alloc:      newIDAllocator(),
		cq:         make(queue, tunnels)[0:0],
	}
	return client, nil
}

func (cli *Client) dial() (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", cli.serverAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	tcpConn := conn.(*net.TCPConn)
	_ = tcpConn.SetKeepAlive(true)
	_ = tcpConn.SetKeepAlivePeriod(time.Second * 180)
	return tcpConn, nil
}

func (cli *Client) createHub(gf infra.Graceful) (hubItem *queueItem, err error) {
	defer func() {
		if err2 := recover(); err2 != nil {
			err = fmt.Errorf("create client hubItem failed: %v", err2)
			log.Errorf("%v", err)
			gf.Shutdown()
		}
	}()

	clientInfo := common.InspectSystemInfo()
	clientInfo.Version = cli.version

	conn, err := cli.dial()
	if err != nil {
		panic(fmt.Errorf("dial failed: %v", err))
	}

	tun := hub.NewTunnel(conn)
	_, challenge, err := tun.ReadPacket()
	if err != nil {
		panic(fmt.Errorf("read challenge failed(%v):%s", tun, err))
	}

	a := common.NewEncryptAlgorithm(cli.secret)
	token, ok := a.ExchangeCipherBlock(challenge)
	if !ok {
		err = errors.New("exchange challenge failed")
		panic(fmt.Errorf("exchange challenge failed(%v)", tun))
	}

	if err = tun.WritePacket(0, token); err != nil {
		panic(fmt.Errorf("write token failed(%v):%s", tun, err))
	}

	tun.SetCipherKey(a.GetRc4key())

	// 上报客户端信息
	if err = tun.WritePacket(0, clientInfo.Encode()); err != nil {
		panic(fmt.Errorf("write client info to server failed(%v): %v", tun, err))
	}

	_, clientInfoResp, err := tun.ReadPacket()
	if err != nil {
		panic(fmt.Errorf("read client info response failed(%v): %s", tun, err))
	}

	if string(clientInfoResp) != "ok" {
		panic(fmt.Errorf("client info exchange failed: %s", string(clientInfoResp)))
	}

	// 用户身份鉴权
	if err = tun.WritePacket(0, common.BuildAuthPacket(cli.conf.Username, cli.conf.Password, cli.backend.Backend)); err != nil {
		panic(fmt.Errorf("write username & password failed(%v):%v", tun, err))
	}

	_, authedPacket, err := tun.ReadPacket()
	if err != nil {
		panic(fmt.Errorf("auth failed(%v):%s", tun, err))
	}

	if string(authedPacket) != "ok" {
		panic(fmt.Errorf("auth failed: %s", string(authedPacket)))
	}

	hubItem = &queueItem{
		Hub: newClientHub(tun),
	}

	return
}

func (cli *Client) addHub(item *queueItem) {
	cli.lock.Lock()
	heap.Push(&cli.cq, item)
	cli.lock.Unlock()
}

func (cli *Client) removeHub(item *queueItem) {
	cli.lock.Lock()
	heap.Remove(&cli.cq, item.index)
	cli.lock.Unlock()
}

func (cli *Client) fetchHub() *queueItem {
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

func (cli *Client) dropHub(item *queueItem) {
	cli.lock.Lock()
	item.priority -= 1
	heap.Fix(&cli.cq, item.index)
	cli.lock.Unlock()
}

func (cli *Client) handleConnection(item *queueItem, conn *net.TCPConn) {
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

func (cli *Client) listen(ctx context.Context, gf infra.Graceful) error {
	ln, err := net.Listen("tcp", cli.backend.Listen)
	if err != nil {
		return err
	}

	defer func() { _ = ln.Close() }()

	log.Debugf("listen on %s for %s ...", cli.backend.Listen, cli.backend.Backend)

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

			log.Debugf("new connection from %v", conn.RemoteAddr())

			cli.initConnToRemote.Do(func() {
				cli.initialize(ctx, gf)
				// 第一次连接本地端口时，延迟3s先建立与服务端的连接
				log.Debugf("connect to server %s...", cli.backend.Backend)
				time.Sleep(3 * time.Second)
			})

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
func (cli *Client) Start(ctx context.Context, gf infra.Graceful) error {
	return cli.listen(ctx, gf)
}

func (cli *Client) initialize(ctx context.Context, gf infra.Graceful) {
	for i := 0; i < cap(cli.cq); i++ {
		go func(index int) {
			defer common.ErrorHandler()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					h, err := cli.createHub(gf)
					if err != nil {
						log.Errorf("tunnel %d for %s reconnect failed", index, cli.backend.Backend)
						time.Sleep(time.Second * 15)
						continue
					}

					func() {
						log.Debugf("tunnel %d for %s connect succeed", index, cli.backend.Backend)
						defer func() {
							cli.removeHub(h)
							log.Warningf("tunnel %d for %s disconnected", index, cli.backend.Backend)
						}()

						cli.addHub(h)
						h.Start()
					}()
				}
			}
		}(i)
	}
}

func (cli *Client) Status() {
	defer cli.lock.Unlock()
	cli.lock.Lock()
	for _, h := range cli.cq {
		h.Status()
	}
}
