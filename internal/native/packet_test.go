package native

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestDatagramBoundariesSurviveFragmentedAndCoalescedFrames(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	c := &packetConn{Conn: a, source: 12345, target: 53, expires: time.Now().Add(time.Minute)}
	done := make(chan error, 1)
	go func() {
		var h [8]byte
		if _, err := io.ReadFull(b, h[:]); err != nil {
			done <- err
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(h[6:]))
		if _, err := io.ReadFull(b, body); err != nil {
			done <- err
			return
		}
		frame := append(h[:], body...)
		// The next datagram has an empty payload; neither is a stream EOF.
		empty := append([]byte(nil), h[:]...)
		binary.BigEndian.PutUint16(empty[6:], 0)
		if _, err := b.Write(frame[:3]); err != nil {
			done <- err
			return
		}
		_, err := b.Write(append(frame[3:], empty...))
		done <- err
	}()
	if n, err := c.Write([]byte("datagram")); err != nil || n != 8 {
		t.Fatal(n, err)
	}
	buf := make([]byte, 3)
	if n, err := c.Read(buf); err != nil || n != 3 || string(buf) != "dat" {
		t.Fatal(n, err, string(buf))
	}
	if n, err := c.Read(buf); err != nil || n != 0 {
		t.Fatal("truncation corrupted next datagram", n, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestInvalidDatagramFramesCloseTheTransport(t *testing.T) {
	for _, field := range []string{"magic", "status", "source", "target", "oversized"} {
		t.Run(field, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(time.Second))
			b.SetDeadline(time.Now().Add(time.Second))
			c := &packetConn{Conn: a, source: 12345, target: 53, expires: time.Now().Add(time.Minute)}
			h := []byte{0xaa, 0, 0x30, 0x39, 0, 53, 0, 0}
			switch field {
			case "magic":
				h[0] = 0
			case "status":
				h[1] = 1
			case "source":
				h[2] = 0
			case "target":
				h[5] = 22
			case "oversized":
				binary.BigEndian.PutUint16(h[6:], 65535)
			}
			go b.Write(h)
			if _, err := c.Read(make([]byte, 32)); err == nil {
				t.Fatal("invalid frame accepted")
			}
			if _, err := b.Write([]byte{0}); err == nil {
				t.Fatal("invalid stream left open")
			}
		})
	}
}

func TestDatagramDeadlinesCannotExtendGrantExpiry(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &packetConn{Conn: a, expires: time.Now().Add(30 * time.Millisecond)}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := c.Read(make([]byte, 64))
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("grant expiry was reset", err)
	}
}

func TestSessionProtocolMismatchDoesNotConsumeOrReuseGrant(t *testing.T) {
	s := exampleSession("https://gateway.example")
	s.Resources[0].Ticket.Protocol = "udp"
	if err := s.Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserveNetwork("tcp", s.Resources[0].Address); err == nil {
		t.Fatal("UDP grant reused for TCP")
	}
	if s.uses[s.Resources[0].Address] != 0 {
		t.Fatal("local mismatch consumed a grant use")
	}
	if _, err := s.reserveNetwork("udp", s.Resources[0].Address); err != nil {
		t.Fatal(err)
	}
}
