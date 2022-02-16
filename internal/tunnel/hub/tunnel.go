package hub

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/mylxsw/secure-tunnel/internal/tunnel/common"
	"io"
	"net"
	"sync"
)

const (
	PacketSize = 8192
)

var ErrTooLarge = fmt.Errorf("tunnel.Read: packet too large")

var mPool = NewMPool(PacketSize)

// Tunnel packet header
// a Tunnel packet consists of a header and a body
// Len is the length of subsequent packet body
type header struct {
	LinkID uint16
	Len    uint16
}

type Tunnel struct {
	*common.Connection

	lock sync.Mutex // protect concurrent write
	err  error      // write error
}

func NewTunnel(conn net.Conn) *Tunnel {
	var tun Tunnel
	tun.Connection = common.NewConnection(
		conn,
		bufio.NewReaderSize(conn, PacketSize*2),
		bufio.NewWriterSize(conn, PacketSize*2),
		nil,
		nil,
	)
	return &tun
}

// WritePacket can write concurrently
func (tun *Tunnel) WritePacket(linkID uint16, data []byte) (err error) {
	defer mPool.Put(data)

	tun.lock.Lock()
	defer tun.lock.Unlock()

	if tun.err != nil {
		return tun.err
	}

	if err = binary.Write(tun, binary.LittleEndian, header{linkID, uint16(len(data))}); err != nil {
		tun.err = err
		_ = tun.Close()
		return err
	}

	if _, err = tun.Write(data); err != nil {
		tun.err = err
		_ = tun.Close()
		return err
	}

	if err = tun.Flush(); err != nil {
		tun.err = err
		_ = tun.Close()
		return err
	}
	return
}

// ReadPacket can't read concurrently
func (tun *Tunnel) ReadPacket() (linkID uint16, data []byte, err error) {
	var h header

	if err = binary.Read(tun, binary.LittleEndian, &h); err != nil {
		return
	}

	if h.Len > PacketSize {
		err = ErrTooLarge
		return
	}

	data = mPool.Get()[0:h.Len]
	if _, err = io.ReadFull(tun, data); err != nil {
		return
	}
	linkID = h.LinkID
	return
}

func (tun *Tunnel) String() string {
	return fmt.Sprintf("Tunnel[%s -> %s]", tun.Conn.LocalAddr(), tun.Conn.RemoteAddr())
}
