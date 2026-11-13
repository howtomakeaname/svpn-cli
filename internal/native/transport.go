package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/howtomakeaname/svpn-cli/internal/headers"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
)

type Dialer struct {
	Session    *Session
	tlsConfig  *tls.Config
	tlcpConfig *tlcp.Config
	Timeout    time.Duration
}

// GatewayError retains a bounded response for explicit private diagnostics.
// Error deliberately omits response headers/body, which may contain identity.
type GatewayError struct {
	Status  int         `json:"status"`
	Headers http.Header `json:"headers"`
	Body    string      `json:"body"`
}

func (e *GatewayError) Error() string {
	return fmt.Sprintf("gateway rejected CONNECT (HTTP %d)", e.Status)
}

func NewDialer(s *Session) (*Dialer, error) {
	if s == nil || s.gatewayURL == nil {
		return nil, errors.New("load and validate a session first")
	}
	if err := s.HeaderProfile.Validate(); err != nil {
		return nil, err
	}
	if s.TLSMode == "tlcp" {
		config, err := newTLCPConfig(s)
		if err != nil {
			return nil, err
		}
		return &Dialer{Session: s, Timeout: 15 * time.Second, tlcpConfig: config}, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if s.CAFile != "" {
		pem, err := os.ReadFile(s.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no certificates")
		}
	}
	name := s.ServerName
	if name == "" {
		name = s.gatewayURL.Hostname()
	}
	// The raw HTTP/1.1 CONNECT transport does not advertise ALPN.
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name, RootCAs: roots}
	if s.CertificateSHA256 != "" {
		pin, err := hex.DecodeString(s.CertificateSHA256)
		if err != nil || len(pin) != sha256.Size {
			return nil, errors.New("invalid explicit certificate fingerprint")
		}
		// Explicit certificate pinning is an alternative trust anchor. Never
		// install this callback automatically after a PKI validation failure.
		// VerifyConnection remains active on resumed TLS sessions as well.
		config.InsecureSkipVerify = true // replaced by mandatory pin/name/time checks below
		config.VerifyConnection = func(state tls.ConnectionState) error {
			return verifyPinnedCertificate(state, pin, name, time.Now())
		}
	}
	return &Dialer{Session: s, Timeout: 15 * time.Second, tlsConfig: config}, nil
}

func verifyPinnedCertificate(state tls.ConnectionState, pin []byte, name string, now time.Time) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("gateway sent no certificate")
	}
	leaf := state.PeerCertificates[0]
	actual := sha256.Sum256(leaf.Raw)
	if len(pin) != sha256.Size || subtle.ConstantTimeCompare(actual[:], pin) != 1 {
		return errors.New("gateway certificate fingerprint mismatch")
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return errors.New("pinned gateway certificate is not currently valid")
	}
	if err := leaf.VerifyHostname(name); err != nil {
		return errors.New("pinned gateway certificate hostname mismatch")
	}
	return nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	protocol := "tcp"
	if network == "udp" || network == "udp4" || network == "udp6" {
		protocol = "udp"
	} else if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("unsupported gateway transport")
	}
	r, err := d.Session.reserveNetwork(protocol, address)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()
	var conn net.Conn
	netDialer := &net.Dialer{Timeout: d.Timeout, KeepAlive: 30 * time.Second}
	if d.tlcpConfig != nil {
		conn, err = (&tlcp.Dialer{NetDialer: netDialer, Config: d.tlcpConfig}).DialContext(ctx, "tcp", d.Session.gatewayURL.Host)
	} else {
		conn, err = (&tls.Dialer{NetDialer: netDialer, Config: d.tlsConfig}).DialContext(ctx, "tcp", d.Session.gatewayURL.Host)
	}
	if err != nil {
		return nil, fmt.Errorf("gateway secure connection: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	header, err := buildConnect(r, conn.LocalAddr().String(), d.Session.HeaderProfile)
	if err != nil {
		return nil, err
	}
	if _, err = io.Copy(conn, bytes.NewReader(header)); err != nil {
		return nil, errors.New("write gateway CONNECT failed")
	}
	reader := bufio.NewReaderSize(conn, 4096)
	var raw bytes.Buffer
	for {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return nil, errors.New("invalid, oversized or incomplete gateway response header")
		}
		if raw.Len()+len(line) > 32768 {
			return nil, errors.New("gateway response header exceeds 32 KiB")
		}
		raw.Write(line)
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			break
		}
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw.Bytes())), nil)
	if err != nil {
		return nil, errors.New("invalid gateway HTTP response")
	}
	if response.StatusCode != http.StatusOK {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		full, parseErr := http.ReadResponse(bufio.NewReader(io.MultiReader(bytes.NewReader(raw.Bytes()), reader)), nil)
		var body []byte
		if parseErr == nil {
			body, _ = io.ReadAll(io.LimitReader(full.Body, 8192))
		}
		return nil, &GatewayError{Status: response.StatusCode, Headers: response.Header, Body: string(body)}
	}
	// The existing bufio reader may already contain the SSH banner or TLS bytes.
	// Never discard it or close response.Body: a CONNECT tunnel has no HTTP body.
	if !stop() && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(d.Session.ExpiresAt); err != nil {
		return nil, err
	}
	wrapped := &tunnelConn{Conn: conn, reader: reader}
	ok = true
	if protocol == "udp" {
		return newPacketConn(wrapped, r.Address, d.Session.ExpiresAt)
	}
	return wrapped, nil
}

func buildConnect(r Resource, sourceAddr string, profile headers.Profile) ([]byte, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	ticket, err := json.Marshal(r.Ticket)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	nonce[6] = (nonce[6] & 0x0f) | 0x40
	nonce[8] = (nonce[8] & 0x3f) | 0x80
	hexID := hex.EncodeToString(nonce[:])
	requestID := hexID[:8] + "-" + hexID[8:12] + "-" + hexID[12:16] + "-" + hexID[16:20] + "-" + hexID[20:]
	var b bytes.Buffer
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\nUser-Agent: %s\r\n", r.Address, r.Address, profile.Agent())
	extra := make(http.Header)
	for k, v := range profile.Gateway {
		extra.Set(k, v)
	}
	if err := extra.Write(&b); err != nil {
		return nil, err
	}
	// Gateway Basic authentication carries JSON directly, without the
	// username:password framing of conventional HTTP Basic authentication.
	fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString(ticket))
	machine := r.Machine
	if machine == "" {
		machine = "localhost"
	}
	fmt.Fprintf(&b, "x-sga-pn: tpn\r\nx-sga-mn: %s\r\nx-rio-seq: %s\r\nRequestId: %s\r\n", machine, requestID, requestID)
	if ip := net.ParseIP(r.Ticket.ClientIp); ip != nil {
		fmt.Fprintf(&b, "x-forwarded-for: %s\r\n", ip.String())
	}
	if host, _, err := net.SplitHostPort(r.Address); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			fmt.Fprintf(&b, "server-ip: %s\r\n", ip.String())
		}
	}
	if _, _, err := net.SplitHostPort(sourceAddr); err == nil {
		fmt.Fprintf(&b, "Source-Addr: %s\r\n", sourceAddr)
	}
	if r.ProxyType != "" {
		fmt.Fprintf(&b, "X-Proxy-Type: %s\r\n", r.ProxyType)
	}
	if r.Ticket.Protocol != "" {
		if r.Ticket.Protocol != "tcp" && r.Ticket.Protocol != "udp" {
			return nil, errors.New("unsupported ticket protocol")
		}
		fmt.Fprintf(&b, "Protocol: %s:\r\n", r.Ticket.Protocol)
	}
	b.WriteString("\r\n")
	if b.Len() > 32768 {
		return nil, errors.New("ticket header exceeds 32 KiB")
	}
	return b.Bytes(), nil
}

type tunnelConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *tunnelConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *tunnelConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return errors.New("transport does not support half close")
}
