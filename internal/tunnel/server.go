//
//   date  : 2014-06-05
//   author: xjdrew
//

package tunnel

import (
	"context"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"net"
)

type ServerHub struct {
	*Hub
	backend    *net.TCPAddr
	authedUser *auth.AuthedUser
}

func (h *ServerHub) handleLink(l *Link) {
	defer exceptionHandler()
	defer h.deleteLink(l.id)

	conn, err := net.DialTCP("tcp", nil, h.backend)
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

func newServerHub(tunnel *Tunnel, backend *net.TCPAddr, authedUser *auth.AuthedUser) *ServerHub {
	h := &ServerHub{
		Hub:        newHub(tunnel),
		backend:    backend,
		authedUser: authedUser,
	}
	h.Hub.onCtrlFilter = h.onCtrl
	return h
}

type Server struct {
	listener net.Listener
	backends map[string]*net.TCPAddr
	secret   string
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
func NewServer(listen string, backends []string, secret string) (*Server, error) {
	ln, err := newListener(listen)
	if err != nil {
		return nil, err
	}

	backendAddrs := make(map[string]*net.TCPAddr)
	for _, backend := range backends {
		addr, err := net.ResolveTCPAddr("tcp", backend)
		if err != nil {
			return nil, err
		}

		backendAddrs[backend] = addr
	}

	return &Server{
		listener: ln,
		backends: backendAddrs,
		secret:   secret,
	}, nil
}
