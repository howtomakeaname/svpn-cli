package native

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const maxDatagram = 65507

// packetConn carries one UDP flow over an authenticated TLS CONNECT stream.
// Each Read consumes one complete datagram, even when the caller's buffer is
// smaller. It is not a raw UDP tunnel: loss on the outer TCP path can block
// subsequent datagrams until TCP recovers.
type packetConn struct {
	net.Conn
	readMu, writeMu sync.Mutex
	source, target  uint16
	address         string
	expires         time.Time
}

func newPacketConn(conn net.Conn, address string, expires time.Time) (net.Conn, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		conn.Close()
		return nil, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		conn.Close()
		return nil, errors.New("invalid UDP target port")
	}
	var nonce [2]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		conn.Close()
		return nil, err
	}
	return &packetConn{Conn: conn, source: binary.BigEndian.Uint16(nonce[:]) | 0x8000, target: uint16(p), address: address, expires: expires}, nil
}

func (c *packetConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var h [8]byte
	if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
		c.Close()
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(h[6:]))
	if h[0] != 0xaa || h[1] != 0 || binary.BigEndian.Uint16(h[2:]) != c.source || binary.BigEndian.Uint16(h[4:]) != c.target || size > maxDatagram {
		c.Close()
		return 0, errors.New("invalid UDP gateway frame")
	}
	n, err := io.ReadFull(c.Conn, p[:min(len(p), size)])
	if err == nil && size > n {
		_, err = io.CopyN(io.Discard, c.Conn, int64(size-n))
	}
	if err != nil {
		c.Close()
	}
	return n, err
}

func (c *packetConn) Write(p []byte) (int, error) {
	if len(p) > maxDatagram {
		return 0, errors.New("UDP datagram exceeds 65507 bytes")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	frame := make([]byte, 8+len(p))
	frame[0] = 0xaa
	binary.BigEndian.PutUint16(frame[2:], c.source)
	binary.BigEndian.PutUint16(frame[4:], c.target)
	binary.BigEndian.PutUint16(frame[6:], uint16(len(p)))
	copy(frame[8:], p)
	for len(frame) > 0 {
		n, err := c.Conn.Write(frame)
		if err != nil {
			c.Close()
			return 0, err
		}
		if n == 0 {
			c.Close()
			return 0, io.ErrNoProgress
		}
		frame = frame[n:]
	}
	return len(p), nil
}

func (c *packetConn) deadline(t time.Time) time.Time {
	if t.IsZero() || t.After(c.expires) {
		return c.expires
	}
	return t
}
func (c *packetConn) SetDeadline(t time.Time) error     { return c.Conn.SetDeadline(c.deadline(t)) }
func (c *packetConn) SetReadDeadline(t time.Time) error { return c.Conn.SetReadDeadline(c.deadline(t)) }
func (c *packetConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(c.deadline(t))
}
func (c *packetConn) RemoteAddr() net.Addr { return udpAddress(c.address) }

type udpAddress string

func (a udpAddress) Network() string { return "udp" }
func (a udpAddress) String() string  { return string(a) }
