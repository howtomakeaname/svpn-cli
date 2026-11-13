package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func echoDial(ctx context.Context, network, address string) (net.Conn, error) {
	a, b := net.Pipe()
	go func() { defer b.Close(); io.Copy(b, b) }()
	return a, nil
}

func startServer(t *testing.T, s *Server, socks bool) (net.Listener, context.CancelFunc) {
	t.Helper()
	l, err := ListenLocal("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		if socks {
			done <- s.ServeSOCKS(ctx, l)
		} else {
			done <- s.ServeHTTP(ctx, l)
		}
	}()
	t.Cleanup(func() {
		cancel()
		l.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("proxy did not shut down")
		}
	})
	return l, cancel
}

func TestHTTPConnectPreservesPipelinedData(t *testing.T) {
	s := New(echoDial, 4)
	l, _ := startServer(t, s, false)
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, "CONNECT inside.example:22 HTTP/1.1\r\nHost: inside.example:22\r\n\r\npipelined")
	r := bufio.NewReader(c)
	response, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	b := make([]byte, len("pipelined"))
	if _, err := io.ReadFull(r, b); err != nil || string(b) != "pipelined" {
		t.Fatalf("lost buffered client bytes %q %v", b, err)
	}
}

func TestSOCKSDomainAndUnsupportedUDP(t *testing.T) {
	seen := make(chan string, 1)
	s := New(func(ctx context.Context, n, a string) (net.Conn, error) { seen <- a; return echoDial(ctx, n, a) }, 4)
	l, _ := startServer(t, s, true)
	for _, cmd := range []byte{1, 3} {
		func() {
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			c.Write([]byte{5, 1, 0})
			var greeting [2]byte
			if _, err := io.ReadFull(c, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
				t.Fatal("bad greeting")
			}
			host := "nonexistent.internal.example"
			request := append([]byte{5, cmd, 0, 3, byte(len(host))}, []byte(host)...)
			request = binary.BigEndian.AppendUint16(request, 22)
			c.Write(request)
			var response [10]byte
			if _, err := io.ReadFull(c, response[:]); err != nil {
				t.Fatal(err)
			}
			if cmd == 3 {
				if response[1] != 7 {
					t.Fatal("UDP command accepted")
				}
				return
			}
			if response[1] != 0 {
				t.Fatal("connect rejected")
			}
			if a := <-seen; a != host+":22" {
				t.Fatal("domain was resolved or changed", a)
			}
			c.Write([]byte("test"))
			var b [4]byte
			if _, err := io.ReadFull(c, b[:]); err != nil || string(b[:]) != "test" {
				t.Fatal("SOCKS relay failed", err)
			}
		}()
	}
}

func TestHTTPForwardingStripsProxyCredentials(t *testing.T) {
	dial := func(ctx context.Context, n, a string) (net.Conn, error) {
		if a != "inside.example:80" {
			t.Errorf("wrong dial target %q", a)
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			r, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				return
			}
			if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" {
				t.Error("hop credentials leaked")
			}
			io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		}()
		return client, nil
	}
	s := New(dial, 4)
	l, _ := startServer(t, s, false)
	u, _ := url.Parse("http://" + l.Addr().String())
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	request, _ := http.NewRequest("GET", "http://inside.example/", nil)
	request.Header.Set("Proxy-Authorization", "Basic secret")
	request.Header.Set("Connection", "X-Hop")
	request.Header.Set("X-Hop", "secret")
	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "ok" {
		t.Fatal(string(b))
	}
}

func TestListenerScopeAndShutdown(t *testing.T) {
	for _, address := range []string{"0.0.0.0:0", "[::]:0", "localhost:0"} {
		if l, err := ListenLocal(address); err == nil {
			l.Close()
			t.Fatalf("accepted nonliteral or public listener %s", address)
		}
	}
	s := New(echoDial, 1)
	l, cancel := startServer(t, s, true)
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{5}) // incomplete greeting must not block shutdown
	cancel()
	_, err = c.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("shutdown left incomplete handshake open")
	}
}

func TestHopHeaderRemoval(t *testing.T) {
	h := http.Header{"Connection": []string{"X-Private"}, "X-Private": []string{"hidden"}, "Proxy-Authorization": []string{"secret"}, "Content-Type": []string{"text/plain"}}
	stripHopHeaders(h)
	if strings.Join(h.Values("X-Private"), "") != "" || h.Get("Proxy-Authorization") != "" || h.Get("Content-Type") != "text/plain" {
		t.Fatal("hop header filtering failed")
	}
}
