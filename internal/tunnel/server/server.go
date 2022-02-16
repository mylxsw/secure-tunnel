package server

import (
	"context"
	"fmt"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/common"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/hub"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"github.com/mylxsw/secure-tunnel/internal/config"
)

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

type ConnStatus struct {
	ID         string           `json:"id"`
	LocalAddr  string           `json:"local_addr"`
	RemoteAddr string           `json:"remote_addr"`
	User       *auth.AuthedUser `json:"user"`
	ReadBytes  int64            `json:"read_bytes"`
	WriteBytes int64            `json:"write_bytes"`
	CreatedAt  time.Time        `json:"created_at"`
}

type connInfo struct {
	net.Conn
	id         string
	readBytes  int64
	writeBytes int64
	createdAt  time.Time
	user       *auth.AuthedUser
}

// NewServer create a tunnel server
func NewServer(listen string, backends []config.BackendServer, secret string) (*Server, error) {
	ln, err := common.NewListener(listen)
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
	defer common.ErrorHandler()

	tun := hub.NewTunnel(conn)
	// authenticate connection
	a := common.NewEncryptAlgorithm(s.secret)
	a.GenerateToken()

	challenge := a.GenerateCipherBlock(nil)
	if err := tun.WritePacket(0, challenge); err != nil {
		log.Errorf("write challenge failed(%v):%s", tun, err)
		return
	}

	_, token, err := tun.ReadPacket()
	if err != nil {
		log.Errorf("read token failed(%v):%s", tun, err)
		return
	}

	if !a.VerifyCipherBlock(token) {
		log.Errorf("verify token failed(%v)", tun)
		return
	}

	tun.SetCipherKey(a.GetRc4key())

	_, authPacket, err := tun.ReadPacket()
	if err != nil {
		log.Errorf("read username & password failed(%v):%s", tun, err)
		return
	}

	username, password, backend := common.ParseAuthPacket(authPacket)
	authedUser, err := author.Login(username, password)
	if err != nil {
		log.Errorf("invalid password for user %s", username)
		_ = tun.WritePacket(0, []byte(fmt.Sprintf("error: invalid password for user %s: %v", username, err)))
		return
	}

	if err := tun.WritePacket(0, []byte("ok")); err != nil {
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

		h := newHub(tun, backend, authedUser)
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

func (s *Server) Status() []ConnStatus {
	s.connectionsLock.RLock()
	defer s.connectionsLock.RUnlock()

	statuses := make([]ConnStatus, 0)
	for _, conn := range s.connections {
		statuses = append(statuses, ConnStatus{
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
