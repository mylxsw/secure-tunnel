//
//   date  : 2015-12-28
//   author: xjdrew
//

package tunnel

import (
	"net"
)

func newListener(addr string) (net.Listener, error) {
	return newTcpListener(addr)
}

func dial(addr string) (net.Conn, error) {
	return dialTcp(addr)
}
