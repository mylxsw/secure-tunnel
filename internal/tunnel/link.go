//
//   date  : 2014-06-04
//   author: xjdrew
//

package tunnel

import (
	"errors"
	"fmt"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/secure-tunnel/internal/auth"
	"net"
	"sync"
	"time"
)

var errPeerClosed = errors.New("errPeerClosed")

type Link struct {
	id          uint16
	conn        *net.TCPConn
	writeBuffer *Buffer // write buffer

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
	return l.setError(errPeerClosed)
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
	b := mpool.Get()
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
			return errPeerClosed
		}

		_, err := l.conn.Write(data)
		mpool.Put(data)
		if err != nil {
			return err
		}
	}
}

// set low level connection
func (l *Link) setConn(conn *net.TCPConn) {
	if l.conn != nil {
		panic(fmt.Errorf("Link(%d) repeated set conn", l.id))
	}
	l.conn = conn
}

// hub function
func (h *Hub) getLink(id uint16) *Link {
	h.ll.RLock()
	defer h.ll.RUnlock()
	return h.links[id]
}

func (h *Hub) deleteLink(id uint16) {
	log.Infof("Link(%d) delete", id)
	h.ll.Lock()
	defer h.ll.Unlock()
	delete(h.links, id)
}

func (h *Hub) createLink(id uint16) *Link {
	log.Infof("Link(%d) new Link over %s", id, h.tunnel)
	h.ll.Lock()
	defer h.ll.Unlock()
	if _, ok := h.links[id]; ok {
		log.Errorf("Link(%d) repeated over %s", id, h.tunnel)
		return nil
	}
	l := &Link{
		id:          id,
		writeBuffer: NewBuffer(16),
	}
	h.links[id] = l
	return l
}

func (h *Hub) startLink(link *Link, conn *net.TCPConn, authedUser *auth.AuthedUser) {
	_ = conn.SetKeepAlive(true)
	_ = conn.SetKeepAlivePeriod(time.Second * 60)
	link.setConn(conn)

	log.With(authedUser).Infof("Link(%d) start %v", link.id, conn.RemoteAddr())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = link.conn.CloseRead() }()

		for {
			data, err := link.read()
			if err != nil {
				if err != errPeerClosed {
					h.sendCommand(link.id, LinkCloseSend)
				}
				break
			}

			h.send(link.id, data)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = link.conn.CloseWrite() }()

		err := link._write()
		if err != errPeerClosed {
			h.sendCommand(link.id, LinkCloseRecv)
		}
	}()
	wg.Wait()
	log.Infof("Link(%d) close", link.id)
}
