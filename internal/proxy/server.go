// Package proxy provides loopback HTTP and SOCKS5 ingress for a native dialer.
package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type DialFunc func(context.Context, string, string) (net.Conn, error)
type Server struct {
	Dial      DialFunc
	sem       chan struct{}
	transport *http.Transport
}

func New(dial DialFunc, maxConnections int) *Server {
	s := &Server{Dial: dial, sem: make(chan struct{}, maxConnections)}
	s.transport = &http.Transport{DialContext: dial, ForceAttemptHTTP2: false, DisableKeepAlives: true, MaxResponseHeaderBytes: 32768, ResponseHeaderTimeout: 30 * time.Second}
	return s
}

// ListenLocal rejects wildcard/hostname listeners to avoid an unauthenticated
// network proxy being exposed accidentally. Remote access can use SSH -L.
func ListenLocal(address string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("proxy listener must use a literal loopback IP")
	}
	return net.Listen("tcp", address)
}

func (s *Server) acquire() bool {
	select {
	case s.sem <- struct{}{}:
		return true
	default:
		return false
	}
}
func (s *Server) release() { <-s.sem }

func (s *Server) ServeHTTP(ctx context.Context, l net.Listener) error {
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.handleHTTP(ctx, w, r) }), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	stop := context.AfterFunc(ctx, func() { srv.Close() })
	defer stop()
	defer s.transport.CloseIdleConnections()
	err := srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) handleHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if !s.acquire() {
		http.Error(w, "connection limit reached", 503)
		return
	}
	defer s.release()
	if r.Method == http.MethodConnect {
		if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
			http.Error(w, "CONNECT must have no request body", 400)
			return
		}
		upstream, err := s.Dial(ctx, "tcp", r.Host)
		if err != nil {
			http.Error(w, "resource tunnel unavailable", 502)
			return
		}
		defer upstream.Close()
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking unsupported", 500)
			return
		}
		client, buffer, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		stop := context.AfterFunc(ctx, func() { client.Close(); upstream.Close() })
		defer stop()
		if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffer.Flush(); err != nil {
			return
		}
		Relay(client, buffer.Reader, upstream)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil || r.Header.Get("Upgrade") != "" {
		http.Error(w, "use absolute-form HTTP or CONNECT", 400)
		return
	}
	request := r.Clone(r.Context())
	request.RequestURI = ""
	stripHopHeaders(request.Header)
	request.Close = true
	response, err := s.transport.RoundTrip(request)
	if err != nil {
		http.Error(w, "resource tunnel unavailable", 502)
		return
	}
	defer response.Body.Close()
	stripHopHeaders(response.Header)
	for k, values := range response.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)
}

func stripHopHeaders(h http.Header) {
	for _, line := range h.Values("Connection") {
		for _, field := range strings.Split(line, ",") {
			h.Del(strings.TrimSpace(field))
		}
	}
	for _, field := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(field)
	}
}

func (s *Server) ServeSOCKS(ctx context.Context, l net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	var active sync.WaitGroup
	defer func() { cancel(); l.Close(); active.Wait() }()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !s.acquire() {
			conn.Close()
			continue
		}
		active.Add(1)
		go func() { defer active.Done(); defer s.release(); s.handleSOCKS(ctx, conn) }()
	}
}

func (s *Server) handleSOCKS(ctx context.Context, client net.Conn) {
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	client.SetDeadline(time.Now().Add(10 * time.Second))
	var header [2]byte
	if _, err := io.ReadFull(client, header[:]); err != nil || header[0] != 5 || header[1] == 0 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	accepted := false
	for _, m := range methods {
		if m == 0 {
			accepted = true
		}
	}
	if !accepted {
		client.Write([]byte{5, 255})
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return
	}
	var req [4]byte
	if _, err := io.ReadFull(client, req[:]); err != nil || req[0] != 5 || req[2] != 0 {
		return
	}
	if req[1] != 1 {
		socksReply(client, 7)
		return
	}
	var host string
	switch req[3] {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(client, b[:]); err != nil {
			return
		}
		host = net.IP(b[:]).String()
	case 4:
		var b [16]byte
		if _, err := io.ReadFull(client, b[:]); err != nil {
			return
		}
		host = net.IP(b[:]).String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(client, size[:]); err != nil || size[0] == 0 {
			return
		}
		b := make([]byte, int(size[0]))
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = string(b)
	default:
		socksReply(client, 8)
		return
	}
	var p [2]byte
	if _, err := io.ReadFull(client, p[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(p[:])
	if port == 0 {
		socksReply(client, 1)
		return
	}
	upstream, err := s.Dial(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		socksReply(client, 2)
		return
	}
	defer upstream.Close()
	stopUpstream := context.AfterFunc(ctx, func() { upstream.Close() })
	defer stopUpstream()
	if err := socksReply(client, 0); err != nil {
		return
	}
	client.SetDeadline(time.Time{})
	Relay(client, client, upstream)
}

func socksReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

// Relay preserves bytes already buffered during an HTTP CONNECT handshake and
// propagates half-closes, so upload EOF does not discard the server's response.
func Relay(client net.Conn, input io.Reader, upstream net.Conn) {
	done := make(chan struct{})
	go func() {
		_, err := io.Copy(upstream, input)
		if err != nil {
			upstream.Close()
			client.Close()
		} else if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		close(done)
	}()
	io.Copy(client, upstream)
	// Server EOF terminates this tunnel; interrupt a still-blocked client read.
	client.Close()
	upstream.Close()
	<-done
}
