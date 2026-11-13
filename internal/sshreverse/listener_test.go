package sshreverse

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/howtomakeaname/svpn-cli/internal/forward"
	"golang.org/x/crypto/ssh"
)

func newSSHServer(t *testing.T, deny bool) (string, ssh.PublicKey, func()) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(key)
	config := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if meta.User() != "test-user" || string(password) != "test-password" {
			return nil, errors.New("invalid test credentials")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	raw := make(chan net.Conn, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		raw <- conn
		defer conn.Close()
		server, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		go func() {
			for channel := range channels {
				channel.Reject(ssh.Prohibited, "remote commands are not supported by this test server")
			}
		}()
		var remote net.Listener
		var streams sync.WaitGroup
		defer func() {
			server.Close()
			if remote != nil {
				remote.Close()
			}
			streams.Wait()
		}()
		for request := range requests {
			if request.Type != "tcpip-forward" || deny || remote != nil {
				request.Reply(false, nil)
				continue
			}
			var bind struct {
				Addr string
				Port uint32
			}
			if ssh.Unmarshal(request.Payload, &bind) != nil {
				request.Reply(false, nil)
				continue
			}
			remote, err = net.Listen("tcp", net.JoinHostPort(bind.Addr, strconv.Itoa(int(bind.Port))))
			if err != nil {
				request.Reply(false, nil)
				continue
			}
			port := uint32(remote.Addr().(*net.TCPAddr).Port)
			request.Reply(true, ssh.Marshal(struct{ Port uint32 }{port}))
			streams.Add(1)
			go func(l net.Listener) {
				defer streams.Done()
				for {
					incoming, err := l.Accept()
					if err != nil {
						return
					}
					streams.Add(1)
					go func() {
						defer streams.Done()
						defer incoming.Close()
						origin := incoming.RemoteAddr().(*net.TCPAddr)
						payload := struct {
							Addr       string
							Port       uint32
							OriginAddr string
							OriginPort uint32
						}{bind.Addr, port, origin.IP.String(), uint32(origin.Port)}
						channel, reqs, err := server.OpenChannel("forwarded-tcpip", ssh.Marshal(payload))
						if err != nil {
							return
						}
						defer channel.Close()
						go ssh.DiscardRequests(reqs)
						upload := make(chan struct{})
						go func() { io.Copy(channel, incoming); channel.CloseWrite(); close(upload) }()
						io.Copy(incoming, channel)
						incoming.Close()
						channel.Close()
						<-upload
					}()
				}
			}(remote)
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			listener.Close()
			select {
			case conn := <-raw:
				conn.Close()
			default:
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("test SSH server did not shut down")
			}
		})
	}
	t.Cleanup(stop)
	return listener.Addr().String(), signer.PublicKey(), stop
}

func configFor(key ssh.PublicKey) *ssh.ClientConfig {
	return &ssh.ClientConfig{User: "test-user", Auth: []ssh.AuthMethod{ssh.Password("test-password")}, HostKeyCallback: ssh.FixedHostKey(key)}
}

func TestRemoteForwardCarriesHTTPAndReleasesPort(t *testing.T) {
	address, key, stopServer := newSSHServer(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var requested string
	dial := func(ctx context.Context, network, target string) (net.Conn, error) {
		requested = target
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	listener, err := Listen(ctx, dial, "ssh.internal.example:22", "127.0.0.1:0", configFor(key))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	remoteAddress := listener.Addr().String()
	if requested != "ssh.internal.example:22" || listener.Addr().(*net.TCPAddr).Port == 0 {
		t.Fatal("SSH did not use the supplied VPN dialer or return an actual port")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "local-service") }))
	defer target.Close()
	done := make(chan error, 1)
	go func() {
		done <- forward.Serve(ctx, listener, (&net.Dialer{}).DialContext, strings.TrimPrefix(target.URL, "http://"), 8)
	}()
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://" + remoteAddress)
	if err != nil {
		t.Fatal("remote -> SSH -> local service failed", err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "local-service" {
		t.Fatal("remote forwarding changed the response")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal("reverse did not stop gracefully", err)
	}
	stopServer()
	rebound, err := net.Listen("tcp", remoteAddress)
	if err != nil {
		t.Fatal("remote port was not released", err)
	}
	rebound.Close()
}

func TestRemoteRefusalHostKeyAndTransportExpiry(t *testing.T) {
	for _, test := range []string{"refused", "host-key", "expiry"} {
		t.Run(test, func(t *testing.T) {
			address, key, _ := newSSHServer(t, test == "refused")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			config := configFor(key)
			rejected := errors.New("host key rejected")
			if test == "host-key" {
				config.HostKeyCallback = func(string, net.Addr, ssh.PublicKey) error { return rejected }
			}
			dial := func(ctx context.Context, network, target string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, network, target)
				if err == nil && test == "expiry" {
					conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
				}
				return conn, err
			}
			listener, err := Listen(ctx, dial, address, "127.0.0.1:0", config)
			if test == "refused" {
				if !errors.Is(err, ErrRemoteListen) {
					t.Fatal("remote listener refusal was not distinguished", err)
				}
				return
			}
			if test == "host-key" {
				if !errors.Is(err, rejected) {
					t.Fatal("host key rejection was not preserved", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan error, 1)
			go func() { _, err := listener.Accept(); accepted <- err }()
			select {
			case err := <-accepted:
				if err == nil {
					t.Fatal("unexpected accepted stream")
				}
			case <-time.After(time.Second):
				t.Fatal("SSH setup cleared the VPN transport expiry")
			}
		})
	}
}
