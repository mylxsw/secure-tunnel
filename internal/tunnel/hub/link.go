package hub

import (
	"fmt"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/common"
	"net"
	"sync"
)

type Link struct {
	ID          uint16
	conn        *net.TCPConn
	writeBuffer *common.Buffer // write buffer

	lock sync.Mutex // protects below fields
	err  error      // if read closed, error to give reads
}

// set err
func (l *Link) setError(err error) bool {
	l.lock.Lock()
	defer l.lock.Unlock()

	if l.err != nil {
		return false
	}

	l.err = err
	return true
}

// closeRead stop read data from Link
func (l *Link) closeRead() bool {
	return l.setError(ErrPeerClosed)
}

// closeWrite stop write data into Link
func (l *Link) closeWrite() bool {
	return l.writeBuffer.Close()
}

// close Link
func (l *Link) close() {
	l.closeRead()
	l.closeWrite()
}

// read data from Link
func (l *Link) read() ([]byte, error) {
	if l.err != nil {
		return nil, l.err
	}
	b := mPool.Get()
	n, err := l.conn.Read(b)
	if err != nil {
		l.setError(err)
		return nil, l.err
	}
	if l.err != nil {
		return nil, l.err
	}
	return b[:n], nil
}

// write data into Link
func (l *Link) write(b []byte) bool {
	return l.writeBuffer.Put(b)
}

// inject data low level connection
func (l *Link) _write() error {
	for {
		data, ok := l.writeBuffer.Pop()
		if !ok {
			return ErrPeerClosed
		}

		_, err := l.conn.Write(data)
		mPool.Put(data)
		if err != nil {
			return err
		}
	}
}

// set low level connection
func (l *Link) setConn(conn *net.TCPConn) {
	if l.conn != nil {
		panic(fmt.Errorf("Link(%d) repeated set conn", l.ID))
	}
	l.conn = conn
}
