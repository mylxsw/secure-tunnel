package server

import (
	"net"
	"time"
)

type tcpListener struct {
	*net.TCPListener
}

func (l *tcpListener) Accept() (net.Conn, error) {
	conn, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = conn.SetKeepAlive(true)
	_ = conn.SetKeepAlivePeriod(time.Second * 180)
	return conn, err
}

// newTCPListener create a tcp listener for server
func newTCPListener(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	tl := tcpListener{ln.(*net.TCPListener)}
	return &tl, nil
}
