package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type observedUDPConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *observedUDPConn) Close() error { c.once.Do(func() { close(c.closed) }); return c.Conn.Close() }

func TestSOCKSUDPAssociationPreservesDatagramsPinsSenderAndCleansUp(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, a, e := echo.ReadFromUDP(buf)
			if e != nil {
				return
			}
			echo.WriteToUDP(buf[:n], a)
		}
	}()
	closed := make(chan struct{})
	called := make(chan string, 8)
	s := New(func(ctx context.Context, network, target string) (net.Conn, error) {
		called <- network + "/" + target
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp", echo.LocalAddr().String())
		if err != nil {
			return nil, err
		}
		return &observedUDPConn{Conn: conn, closed: closed}, nil
	}, 4)
	l, _ := startServer(t, s, true)
	control, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(3 * time.Second))
	control.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, err := io.ReadFull(control, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatal("greeting", err)
	}
	control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	var reply [10]byte
	if _, err := io.ReadFull(control, reply[:]); err != nil || reply[1] != 0 || reply[3] != 1 {
		t.Fatal("association refused", err)
	}
	endpoint := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:]))}
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	header := udpAddressHeader("private.example:53")
	fragment := append(append([]byte(nil), header...), "discard"...)
	fragment[2] = 1
	client.WriteToUDP(fragment, endpoint)
	for _, payload := range []string{"one", "", "three"} {
		packet := append(append([]byte(nil), header...), payload...)
		if _, err := client.WriteToUDP(packet, endpoint); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 256)
		n, _, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		target, body, err := parseUDPAddress(buf[:n])
		if err != nil || target != "private.example:53" || string(body) != payload {
			t.Fatal("message boundary lost", target, string(body), err)
		}
	}
	if target := <-called; target != "udp/private.example:53" {
		t.Fatal("domain or protocol changed", target)
	}
	select {
	case <-called:
		t.Fatal("unexpected extra flow")
	default:
	}
	intruder, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer intruder.Close()
	intruder.WriteToUDP(append(header, "injected"...), endpoint)
	intruder.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := intruder.ReadFromUDP(make([]byte, 256)); err == nil {
		t.Fatal("another source port hijacked association")
	}
	control.Close()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("TCP closure leaked UDP flow")
	}
}

func TestSOCKSUDPAddressRoundTrip(t *testing.T) {
	for _, address := range []string{"192.0.2.53:53", "[2001:db8::53]:53", "internal.example:443"} {
		got, payload, err := parseUDPAddress(append(udpAddressHeader(address), 1, 2, 3))
		if err != nil || got != address || len(payload) != 3 {
			t.Fatal(address, got, err)
		}
	}
}

func FuzzSOCKSUDPAddress(f *testing.F) {
	for _, seed := range [][]byte{nil, {0}, {0, 0, 0, 3, 255}, {0, 0, 1, 1, 127, 0, 0, 1, 0, 53}, udpAddressHeader("[::1]:53"), udpAddressHeader("private.example:53")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		address, payload, err := parseUDPAddress(data)
		if err == nil {
			if address == "" || len(payload) > len(data) {
				t.Fatal("invalid parser result")
			}
		}
	})
}
