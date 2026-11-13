package native

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/howtomakeaname/svpn-cli/internal/headers"
	"github.com/howtomakeaname/svpn-cli/internal/privatefs"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func exampleSession(gateway string) *Session {
	return &Session{Version: 1, Gateway: gateway, ExpiresAt: time.Now().Add(time.Minute), Resources: []Resource{{Address: "inside.example:22", Ticket: TicketJSON{ST: "test-issued-ticket", UserName: "test-user", DeviceID: "test-device", Protocol: "tcp"}, MaxConnections: 8}}}
}

func mockGateway(t *testing.T, status int, handler func(*http.Request)) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler != nil {
			handler(r)
		}
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		// Deliberately coalesce headers and tunnel data into a single TLS write.
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\nSSH-2.0-mock\r\n")
		io.Copy(conn, conn)
	}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func TestNativeGatewayCONNECTAndBufferedBanner(t *testing.T) {
	requests := make(chan *http.Request, 1)
	srv := mockGateway(t, 200, func(r *http.Request) { requests <- r })
	s := exampleSession(srv.URL)
	s.HeaderProfile = headers.Profile{UserAgent: "configured-agent/1", Gateway: map[string]string{"X-Example-Option": "enabled"}}
	if err := s.Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	d, err := NewDialer(s)
	if err != nil {
		t.Fatal(err)
	}
	d.tlsConfig.RootCAs.AddCert(srv.Certificate())
	conn, err := d.DialContext(context.Background(), "tcp", "Inside.Example.:22")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	banner := make([]byte, len("SSH-2.0-mock\r\n"))
	if _, err := io.ReadFull(conn, banner); err != nil || string(banner) != "SSH-2.0-mock\r\n" {
		t.Fatalf("lost early data: %q %v", banner, err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("tunnel echo: %q %v", buf, err)
	}
	r := <-requests
	if r.UserAgent() != "configured-agent/1" || r.Header.Get("X-Example-Option") != "enabled" {
		t.Fatal("configured gateway headers not applied")
	}
	if r.Method != "CONNECT" || r.Host != "inside.example:22" {
		t.Fatalf("wrong destination %s %s", r.Method, r.Host)
	}
	auth := r.Header.Get("Proxy-Authorization")
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		t.Fatal(err)
	}
	var ticket TicketJSON
	if err := json.Unmarshal(decoded, &ticket); err != nil {
		t.Fatal(err)
	}
	if ticket.ST != "test-issued-ticket" || ticket.UserName != "test-user" {
		t.Fatal("ticket was not sent in protocol format")
	}
	if r.Header.Get("Protocol") != "tcp:" {
		t.Fatal("missing protocol header")
	}
}

func TestTLSVerificationAndGatewayRejection(t *testing.T) {
	for _, status := range []int{200, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := mockGateway(t, status, nil)
			s := exampleSession(srv.URL)
			if err := s.Validate(time.Now()); err != nil {
				t.Fatal(err)
			}
			d, err := NewDialer(s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.DialContext(context.Background(), "tcp", "inside.example:22"); err == nil {
				t.Fatal("untrusted TLS certificate accepted")
			}
			d.tlsConfig.RootCAs.AddCert(srv.Certificate())
			if status == 403 {
				if _, err := d.DialContext(context.Background(), "tcp", "inside.example:22"); err == nil {
					t.Fatal("gateway rejection accepted")
				}
			}
		})
	}
}

func TestExplicitCertificatePinning(t *testing.T) {
	srv := mockGateway(t, 200, nil)
	leaf := srv.Certificate()
	pin := sha256.Sum256(leaf.Raw)
	s := exampleSession(srv.URL)
	s.CertificateSHA256 = hex.EncodeToString(pin[:])
	if err := s.Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	d, err := NewDialer(s)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", "inside.example:22")
	if err != nil {
		t.Fatal("valid pinned gateway rejected:", err)
	}
	conn.Close()
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	for _, test := range []struct {
		name string
		now  time.Time
		pin  []byte
	}{
		{"wrong.example", time.Now(), pin[:]},
		{"127.0.0.1", leaf.NotAfter.Add(time.Second), pin[:]},
		{"127.0.0.1", leaf.NotBefore.Add(-time.Second), pin[:]},
		{"127.0.0.1", time.Now(), make([]byte, 32)},
	} {
		if err := verifyPinnedCertificate(state, test.pin, test.name, test.now); err == nil {
			t.Fatal("accepted mismatched, expired or premature certificate")
		}
	}
	if verifyPinnedCertificate(tls.ConnectionState{}, pin[:], "127.0.0.1", time.Now()) == nil {
		t.Fatal("accepted missing certificate")
	}
}

func TestResourceScopeExpiryAndExhaustion(t *testing.T) {
	s := exampleSession("https://gateway.example:9443")
	s.Resources[0].MaxConnections = 1
	if err := s.Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"other.example:22", "inside.example:23", "inside.example:0", "inside.example:22\r\nInjected: yes"} {
		if _, err := s.reserve(a); err == nil {
			t.Fatalf("accepted %q", a)
		}
	}
	if _, err := s.reserve("inside.example:22"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserve("inside.example:22"); err == nil {
		t.Fatal("reused exhausted grant")
	}
	s.ExpiresAt = time.Now().Add(-time.Second)
	if _, err := s.reserve("inside.example:22"); err == nil {
		t.Fatal("accepted expired grant")
	}
}

func TestPrivateSessionAndStrictJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := exampleSession("https://gateway.example:9443")
	b, _ := json.Marshal(s)
	file, err := privatefs.CreateTemp(filepath.Dir(path), ".session-*")
	if err != nil {
		t.Fatal(err)
	}
	file.Write(b)
	name := file.Name()
	file.Close()
	if err := os.Rename(name, path); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		os.Chmod(path, 0644)
		if _, err := LoadSession(path); err == nil {
			t.Fatal("accepted group/world-readable credentials")
		}
		os.Chmod(path, 0600)
	}
	if _, err := LoadSession(path); err != nil {
		t.Fatal(err)
	}
	b = append(b, []byte(" {}")...)
	os.WriteFile(path, b, 0600)
	if _, err := LoadSession(path); err == nil {
		t.Fatal("accepted trailing JSON")
	}
}

func TestHeaderLimitAndContextCancellation(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// A context canceled before dialing must not initiate a connection.
	s := exampleSession("https://" + l.Addr().String())
	s.Validate(time.Now())
	d, _ := NewDialer(s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.DialContext(ctx, "tcp", "inside.example:22"); err == nil {
		t.Fatal("canceled dial succeeded")
	}
	r := s.Resources[0]
	r.Ticket.ST = strings.Repeat("x", 32768)
	if _, err := buildConnect(r, "127.0.0.1:12345", headers.Profile{}); err == nil {
		t.Fatal("accepted oversized credential header")
	}
}
