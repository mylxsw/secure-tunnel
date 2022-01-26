//
//   date  : 2015-12-28
//   author: xjdrew
//

package tunnel

import (
	"net"
	"time"
)

type TcpListener struct {
	*net.TCPListener
}

func (l *TcpListener) Accept() (net.Conn, error) {
	conn, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = conn.SetKeepAlive(true)
	_ = conn.SetKeepAlivePeriod(KeepalivePeriod)
	return conn, err
}

// create a tcp listener for server
func newTcpListener(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	tl := TcpListener{ln.(*net.TCPListener)}
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
