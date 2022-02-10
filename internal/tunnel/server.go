//
//   date  : 2014-06-05
//   author: xjdrew
//

package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/mylxsw/secure-tunnel/internal/config"
	"github.com/secmask/go-redisproto"
)

type ServerHub struct {
	*Hub
	backend    *Backend
	authedUser *auth.AuthedUser
}

func (h *ServerHub) handleLink(l *Link) {
	defer exceptionHandler()
	defer h.deleteLink(l.id)

	conn, err := net.DialTCP("tcp", nil, h.backend.Addr)
	if err != nil {
		log.Errorf("Link(%d) connect to serverAddr failed, err:%v", l.id, err)
		h.sendCommand(l.id, LinkClose)
		h.deleteLink(l.id)
		return
	}

	h.startLink(l, conn, h.authedUser)
}

func (h *ServerHub) onCtrl(cmd Command) bool {
	id := cmd.ID
	switch cmd.Cmd {
	case LinkCreate:
		l := h.createLink(id)
		if l != nil {
			go h.handleLink(l)
		} else {
			h.sendCommand(id, LinkClose)
		}
		return true
	case TunHeartbeat:
		h.sendCommand(id, TunHeartbeat)
		return true
	}
	return false
}

func newServerHub(tunnel *Tunnel, backend *Backend, authedUser *auth.AuthedUser) *ServerHub {
	h := &ServerHub{
		Hub:        newHub(tunnel),
		backend:    backend,
		authedUser: authedUser,
	}
	h.Hub.onCtrlFilter = h.onCtrl
	h.Hub.onDataFilter = func(isResp bool, link *Link, data []byte) {
		switch backend.Backend.Protocol {
		case "redis":
			redisProtocolFilter(isResp, link, data, authedUser, backend)
		default:
		}
	}
	return h
}

func redisProtocolFilter(isResp bool, link *Link, data []byte, authedUser *auth.AuthedUser, backend *Backend) {
	if isResp {
		if backend.Backend.LogResponse {
			log.WithFields(log.Fields{
				"user":    authedUser,
				"backend": backend.Backend,
				"link":    link.id,
				"data":    string(data),
			}).Info("audit:resp")
		}
	} else {
		cmd, err := redisproto.NewParser(bytes.NewBuffer(data)).ReadCommand()
		if err != nil {
			log.With(authedUser).Errorf("parse redis protocol failed: %v", err)
			return
		}

		strs := make([]string, 0)
		for i := 0; i < cmd.ArgCount(); i++ {
			strs = append(strs, string(cmd.Get(i)))
		}

		log.WithFields(log.Fields{
			"user":    authedUser,
			"backend": backend.Backend,
			"link":    link.id,
			"data":    strings.Join(strs, " "),
		}).Info("audit:req")
	}
}

type Server struct {
	listener net.Listener
	backends map[string]*Backend
	secret   string
}

type Backend struct {
	Addr    *net.TCPAddr
	Backend config.BackendServer
}

func (s *Server) handleConnection(conn net.Conn, author auth.Author) {
	defer func() { _ = conn.Close() }()
	defer exceptionHandler()

	tunnel := newTunnel(conn)
	// authenticate connection
	a := newEncryptAlgorithm(s.secret)
	a.generateToken()

	challenge := a.generateCipherBlock(nil)
	if err := tunnel.WritePacket(0, challenge); err != nil {
		log.Errorf("write challenge failed(%v):%s", tunnel, err)
		return
	}

	_, token, err := tunnel.ReadPacket()
	if err != nil {
		log.Errorf("read token failed(%v):%s", tunnel, err)
		return
	}

	if !a.VerifyCipherBlock(token) {
		log.Errorf("verify token failed(%v)", tunnel)
		return
	}

	tunnel.SetCipherKey(a.GetRc4key())

	_, authPacket, err := tunnel.ReadPacket()
	if err != nil {
		log.Errorf("read username & password failed(%v):%s", tunnel, err)
		return
	}

	username, password, backend := parseAuthPacket(authPacket)
	authedUser, err := author.Login(username, password)
	if err != nil {
		log.Errorf("invalid password for user %s", username)
		_ = tunnel.WritePacket(0, []byte(fmt.Sprintf("error: invalid password for user %s: %v", username, err)))
		return
	}

	if err := tunnel.WritePacket(0, []byte("ok")); err != nil {
		log.Errorf("write authed packet to client failed: %v", err)
		return
	}

	if backend, ok := s.backends[backend]; ok {
		h := newServerHub(tunnel, backend, authedUser)
		h.Start()
	}
}

func (s *Server) Start(ctx context.Context, resolver infra.Resolver) error {
	return resolver.ResolveWithError(func(author auth.Author) error {
		defer func() { _ = s.listener.Close() }()

		for {
			select {
			case <-ctx.Done():
				return nil
			default:
				conn, err := s.listener.Accept()
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
						log.Warningf("accept failed temporary: %s", netErr.Error())
						continue
					} else {
						return err
					}
				}
				log.Warningf("new connection from %v", conn.RemoteAddr())
				go s.handleConnection(conn, author)
			}
		}
	})
}

func (s *Server) Status() {
}

// NewServer create a tunnel server
func NewServer(listen string, backends []config.BackendServer, secret string) (*Server, error) {
	ln, err := newListener(listen)
	if err != nil {
		return nil, err
	}

	backendAddrs := make(map[string]*Backend)
	for _, backend := range backends {
		addr, err := net.ResolveTCPAddr("tcp", backend.Addr)
		if err != nil {
			return nil, err
		}

		backendAddrs[backend.Name] = &Backend{Addr: addr, Backend: backend}
	}

	return &Server{
		listener: ln,
		backends: backendAddrs,
		secret:   secret,
	}, nil
}
