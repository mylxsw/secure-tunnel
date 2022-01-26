//
//   date  : 2014-06-05
//   author: xjdrew
//

package tunnel

import (
	"github.com/mylxsw/asteria/log"
	"net"
)

// server hub
type ServerHub struct {
	*Hub
	baddr       *net.TCPAddr
	currentUser string
}

func (h *ServerHub) handleLink(l *link) {
	defer Recover()
	defer h.deleteLink(l.id)

	conn, err := net.DialTCP("tcp", nil, h.baddr)
	if err != nil {
		log.Errorf("link(%d) connect to serverAddr failed, err:%v", l.id, err)
		h.SendCmd(l.id, LINK_CLOSE)
		h.deleteLink(l.id)
		return
	}

	h.startLink(l, conn, h.currentUser)
}

func (h *ServerHub) onCtrl(cmd Cmd) bool {
	id := cmd.Id
	switch cmd.Cmd {
	case LINK_CREATE:
		l := h.createLink(id)
		if l != nil {
			go h.handleLink(l)
		} else {
			h.SendCmd(id, LINK_CLOSE)
		}
		return true
	case TUN_HEARTBEAT:
		h.SendCmd(id, TUN_HEARTBEAT)
		return true
	}
	return false
}

func newServerHub(tunnel *Tunnel, baddr *net.TCPAddr, currentUser string) *ServerHub {
	h := &ServerHub{
		Hub:         newHub(tunnel),
		baddr:       baddr,
		currentUser: currentUser,
	}
	h.Hub.onCtrlFilter = h.onCtrl
	return h
}

// tunnel server
type Server struct {
	ln           net.Listener
	backendConns map[string]*net.TCPAddr
	secret       string
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	defer Recover()

	tunnel := newTunnel(conn)
	// authenticate connection
	a := NewEncryptAlgorithm(s.secret)
	a.GenerateToken()

	challenge := a.GenerateCipherBlock(nil)
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
	if !s.ValidateUser(username, password) {
		log.Errorf("invalid password for user %s", username)
		return
	}

	if backend, ok := s.backendConns[backend]; ok {
		h := newServerHub(tunnel, backend, username)
		h.Start()
	}
}

func (s *Server) ValidateUser(username, password string) bool {
	return username == "guanyiyao" && password == "123456"
}

func (s *Server) Start() error {
	defer s.ln.Close()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				log.Warningf("accept failed temporary: %s", netErr.Error())
				continue
			} else {
				return err
			}
		}
		log.Warningf("new connection from %v", conn.RemoteAddr())
		go s.handleConn(conn)
	}
}

func (s *Server) Status() {
}

// create a tunnel server
func NewServer(listen string, backends []string, secret string) (*Server, error) {
	ln, err := newListener(listen)
	if err != nil {
		return nil, err
	}

	backendConns := make(map[string]*net.TCPAddr)

	for _, backend := range backends {
		baddr, err := net.ResolveTCPAddr("tcp", backend)
		if err != nil {
			return nil, err
		}

		backendConns[backend] = baddr
	}

	s := &Server{
		ln:           ln,
		backendConns: backendConns,
		secret:       secret,
	}
	return s, nil
}
