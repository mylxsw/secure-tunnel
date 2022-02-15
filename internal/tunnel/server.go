//
//   date  : 2014-06-05
//   author: xjdrew
//

package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/mylxsw/secure-tunnel/internal/config"
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
		if backend.Backend.Protocol == "" {
			return
		}

		switch backend.Backend.Protocol {
		case "redis":
			redisProtocolFilter(isResp, link, data, authedUser, backend)
		case "mysql":
			mysqlProtocolFilter(isResp, link, data, authedUser, backend)
		default:
			defaultProtocolFilter(isResp, link, data, authedUser, backend)
		}
	}
	return h
}

type Server struct {
	listener        net.Listener
	backends        map[string]*Backend
	secret          string
	connections     map[string]*connInfo
	connectionsLock sync.RWMutex
}

type Backend struct {
	Addr    *net.TCPAddr
	Backend config.BackendServer
}

type connInfo struct {
	net.Conn
	id         string
	readBytes  int64
	writeBytes int64
	createdAt  time.Time
	user       *auth.AuthedUser
}

// Read reads data from the connection.
// Read can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetReadDeadline.
func (info *connInfo) Read(b []byte) (n int, err error) {
	n, err = info.Conn.Read(b)
	atomic.AddInt64(&info.readBytes, int64(n))
	return
}

// Write writes data to the connection.
// Write can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetWriteDeadline.
func (info *connInfo) Write(b []byte) (n int, err error) {
	n, err = info.Conn.Write(b)
	atomic.AddInt64(&info.writeBytes, int64(n))
	return
}

func (s *Server) handleConnection(conn *connInfo, author auth.Author) {
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
		conn.user = authedUser

		s.connectionsLock.Lock()
		s.connections[conn.id] = conn
		s.connectionsLock.Unlock()

		defer func() {
			s.connectionsLock.Lock()
			delete(s.connections, conn.id)
			s.connectionsLock.Unlock()
		}()

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
				cinfo := connInfo{
					Conn:      conn,
					id:        fmt.Sprintf("%s-%s", conn.LocalAddr().String(), conn.RemoteAddr().String()),
					createdAt: time.Now(),
				}
				log.With(cinfo).Debugf("new connection from %v", conn.RemoteAddr())
				go s.handleConnection(&cinfo, author)
			}
		}
	})
}

type ServerConnStatus struct {
	ID         string           `json:"id"`
	LocalAddr  string           `json:"local_addr"`
	RemoteAddr string           `json:"remote_addr"`
	User       *auth.AuthedUser `json:"user"`
	ReadBytes  int64            `json:"read_bytes"`
	WriteBytes int64            `json:"write_bytes"`
	CreatedAt  time.Time        `json:"created_at"`
}

func (s *Server) Status() []ServerConnStatus {
	s.connectionsLock.RLock()
	defer s.connectionsLock.RUnlock()

	statuses := make([]ServerConnStatus, 0)
	for _, conn := range s.connections {
		statuses = append(statuses, ServerConnStatus{
			ID:         conn.id,
			LocalAddr:  conn.Conn.LocalAddr().String(),
			RemoteAddr: conn.Conn.RemoteAddr().String(),
			User:       conn.user,
			ReadBytes:  conn.readBytes,
			WriteBytes: conn.writeBytes,
			CreatedAt:  conn.createdAt,
		})
	}

	return statuses
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
		listener:    ln,
		backends:    backendAddrs,
		secret:      secret,
		connections: make(map[string]*connInfo),
	}, nil
}
