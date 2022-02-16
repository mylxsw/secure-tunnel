package common

import (
	"net"
)

func NewListener(addr string) (net.Listener, error) {
	return NewTCPListener(addr)
}

func Dial(addr string) (net.Conn, error) {
	return dialTcp(addr)
}
