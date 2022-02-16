package common

import (
	"net"
	"time"
)

const (
	KeepalivePeriod = time.Second * 180
)

type TCPListener struct {
	*net.TCPListener
}

func (l *TCPListener) Accept() (net.Conn, error) {
	conn, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = conn.SetKeepAlive(true)
	_ = conn.SetKeepAlivePeriod(KeepalivePeriod)
	return conn, err
}

// NewTCPListener create a tcp listener for server
func NewTCPListener(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	tl := TCPListener{ln.(*net.TCPListener)}
	return &tl, nil
}

// for client
func dialTcp(addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	tcpConn := conn.(*net.TCPConn)
	_ = tcpConn.SetKeepAlive(true)
	_ = tcpConn.SetKeepAlivePeriod(KeepalivePeriod)
	return tcpConn, nil
}
