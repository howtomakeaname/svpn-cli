// Package native implements the TCP gateway transport.
// Device authentication and per-resource ticket acquisition live in control/engine.
package native

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/howtomakeaname/svpn-cli/internal/headers"
	"github.com/howtomakeaname/svpn-cli/internal/privatefs"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TicketJSON carries the gateway identity and resource grant claims.
// Field casing is significant to the authentication protocol.
type TicketJSON struct {
	UserName   string
	DeviceID   string
	ST         string
	AppID      string
	AppName    string
	AppVersion string
	ReqUrl     string
	ProcName   string
	Source     string
	PID        int
	ServiceId  string
	TenantId   string
	ClientIp   string
	Protocol   string
}

type Resource struct {
	Machine        string     `json:"machine,omitempty"`
	Address        string     `json:"address"`
	Ticket         TicketJSON `json:"ticket"`
	MaxConnections int        `json:"max_connections"`
	ProxyType      string     `json:"proxy_type,omitempty"`
}

// Session contains independently supplied, already-issued resource tickets.
// It is not an export format claimed to be supported by the official client.
type Session struct {
	Version           int             `json:"version"`
	Gateway           string          `json:"gateway"`
	ServerName        string          `json:"server_name,omitempty"`
	CAFile            string          `json:"ca_file,omitempty"`
	CertificateSHA256 string          `json:"certificate_sha256,omitempty"`
	HeaderProfile     headers.Profile `json:"header_profile,omitempty"`
	ExpiresAt         time.Time       `json:"expires_at"`
	Resources         []Resource      `json:"resources"`
	mu                sync.Mutex
	uses              map[string]int
	byAddress         map[string]int
	gatewayURL        *url.URL
}

func CanonicalAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("invalid host:port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("invalid port")
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if len(host) == 0 || len(host) > 253 {
			return "", fmt.Errorf("invalid hostname")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", fmt.Errorf("invalid hostname label")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return "", fmt.Errorf("invalid hostname character")
				}
			}
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(p)), nil
}

func LoadSession(path string) (*Session, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := privatefs.Check(f); err != nil {
		return nil, err
	}
	if info.Size() > 1<<20 {
		return nil, errors.New("session exceeds 1 MiB")
	}
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	dec.DisallowUnknownFields()
	var s Session
	if err := dec.Decode(&s); err != nil {
		return nil, errors.New("invalid session JSON or unknown fields")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing data in session")
	}
	if s.CAFile != "" && !filepath.IsAbs(s.CAFile) {
		s.CAFile = filepath.Join(filepath.Dir(path), s.CAFile)
	}
	if err := s.Validate(time.Now()); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *Session) Validate(now time.Time) error {
	if err := s.HeaderProfile.Validate(); err != nil {
		return err
	}
	if s.Version != 1 {
		return errors.New("unsupported session version")
	}
	u, err := url.Parse(s.Gateway)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("gateway must be an HTTPS origin without credentials, path, query or fragment")
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "443")
	}
	if _, err := CanonicalAddress(u.Host); err != nil {
		return errors.New("invalid gateway address")
	}
	if !s.ExpiresAt.After(now) {
		return errors.New("session has expired")
	}
	if len(s.Resources) == 0 || len(s.Resources) > 256 {
		return errors.New("session needs 1 to 256 explicit resources")
	}
	if strings.ContainsAny(s.ServerName, "\r\n\x00") {
		return errors.New("invalid TLS server name")
	}
	if s.CertificateSHA256 != "" {
		pin := strings.ReplaceAll(s.CertificateSHA256, ":", "")
		decoded, err := hex.DecodeString(pin)
		if err != nil || len(decoded) != 32 {
			return errors.New("certificate_sha256 must be a 32-byte SHA-256 fingerprint")
		}
		s.CertificateSHA256 = hex.EncodeToString(decoded)
	}
	s.byAddress = make(map[string]int)
	s.uses = make(map[string]int)
	for i := range s.Resources {
		r := &s.Resources[i]
		a, err := CanonicalAddress(r.Address)
		if err != nil {
			return fmt.Errorf("invalid resource address at index %d", i)
		}
		if _, exists := s.byAddress[a]; exists {
			return errors.New("duplicate resource address")
		}
		if r.Ticket.ST == "" || r.Ticket.UserName == "" || r.Ticket.DeviceID == "" {
			return fmt.Errorf("resource %d requires issued ST, UserName and DeviceID", i)
		}
		if r.Ticket.Protocol != "" && r.Ticket.Protocol != "tcp" && r.Ticket.Protocol != "udp" {
			return errors.New("unsupported resource ticket protocol")
		}
		if r.MaxConnections < 1 || r.MaxConnections > 10000 {
			return errors.New("max_connections must match the issued ticket allowance, from 1 to 10000")
		}
		if strings.ContainsAny(r.ProxyType, "\r\n\x00") {
			return errors.New("invalid proxy type")
		}
		if strings.ContainsAny(r.Machine, "\r\n\x00") {
			return errors.New("invalid device display name")
		}
		for _, c := range r.ProxyType {
			if c < 32 || c > 126 {
				return errors.New("proxy type must contain printable ASCII only")
			}
		}
		r.Address = a
		s.byAddress[a] = i
	}
	s.gatewayURL = u
	return nil
}

// reserve fails closed for unlisted, expired or exhausted grants. A failed
// gateway attempt consumes a use too, avoiding accidental ticket overuse.
func (s *Session) reserve(address string) (Resource, error) { return s.reserveNetwork("tcp", address) }

func (s *Session) reserveNetwork(network, address string) (Resource, error) {
	a, err := CanonicalAddress(address)
	if err != nil {
		return Resource{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ExpiresAt.After(time.Now()) {
		return Resource{}, errors.New("session has expired; acquire fresh tickets")
	}
	i, ok := s.byAddress[a]
	if !ok {
		return Resource{}, errors.New("target is not in the explicit resource list")
	}
	r := s.Resources[i]
	protocol := r.Ticket.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	if protocol != network {
		return Resource{}, errors.New("resource ticket does not authorize the requested protocol")
	}
	if s.uses[a] >= r.MaxConnections {
		return Resource{}, errors.New("resource ticket connection allowance exhausted")
	}
	s.uses[a]++
	return r, nil
}
