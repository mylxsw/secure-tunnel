package common

import (
	"bufio"
	"crypto/rc4"
	"net"
)

type Connection struct {
	net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	enc    *rc4.Cipher
	dec    *rc4.Cipher
}

func NewConnection(conn net.Conn, reader *bufio.Reader, writer *bufio.Writer, enc *rc4.Cipher, dec *rc4.Cipher) *Connection {
	return &Connection{
		Conn:   conn,
		reader: reader,
		writer: writer,
		enc:    enc,
		dec:    dec,
	}
}

func (conn *Connection) SetCipherKey(key []byte) {
	conn.enc, _ = rc4.NewCipher(key)
	conn.dec, _ = rc4.NewCipher(key)
}

func (conn *Connection) Read(b []byte) (int, error) {
	n, err := conn.reader.Read(b)
	if n > 0 && conn.dec != nil {
		conn.dec.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

func (conn *Connection) Write(b []byte) (int, error) {
	if conn.enc != nil {
		conn.enc.XORKeyStream(b, b)
	}
	return conn.writer.Write(b)
}

func (conn *Connection) Flush() error {
	return conn.writer.Flush()
}
