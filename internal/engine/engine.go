// Package engine obtains per-resource grants and opens independent iOA tunnels.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/howtomakeaname/svpn-cli/internal/control"
	"github.com/howtomakeaname/svpn-cli/internal/native"
	"github.com/howtomakeaname/svpn-cli/internal/policy"
)

type Identity struct {
	ID                       int64
	UserID, DeviceID, Ticket string
	TicketType               int
}
type Engine struct {
	Client                    *control.Client
	Identity                  Identity
	CertificateSHA256, CAFile string
	GatewayTLS                string
	mu                        sync.Mutex
	cache                     map[string]*cachedGrant
}
type cachedGrant struct {
	ready     chan struct{}
	dialer    *native.Dialer
	expires   time.Time
	remaining int
	err       error
}

func New(client *control.Client, identity Identity) (*Engine, error) {
	if client == nil || identity.ID <= 0 || identity.UserID == "" || identity.DeviceID != client.MID || identity.Ticket == "" || identity.TicketType != 0 {
		return nil, errors.New("a device-bound exchanged login identity is required")
	}
	return &Engine{Client: client, Identity: identity, cache: map[string]*cachedGrant{}}, nil
}

func (e *Engine) FetchPolicy(ctx context.Context) (*policy.Policy, error) {
	r, err := e.Client.Call(ctx, "/cmd.cgi", "10006622", map[string]any{"PolicyMd5": "", "BusinessList": []any{}, "Uid": strconv.FormatInt(e.Identity.ID, 10)})
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return policy.Parse(data)
}

// Issue creates a new grant. No credentials or tickets are logged or stored by
// this package; an explicit CLI export can save the returned private session.
func (e *Engine) Issue(ctx context.Context, address string, area *policy.Area) (*native.Session, error) {
	return e.IssueNetwork(ctx, "tcp", address, area)
}

// IssueNetwork keeps the requested grant protocol bound to the transport.
func (e *Engine) IssueNetwork(ctx context.Context, network, address string, area *policy.Area) (*native.Session, error) {
	if network != "tcp" && network != "udp" {
		return nil, errors.New("unsupported resource transport")
	}
	address, err := native.CanonicalAddress(address)
	if err != nil {
		return nil, err
	}
	if area == nil || area.ID == "" || area.SetID == "" {
		return nil, errors.New("resource has no issued gateway route")
	}
	if (network == "udp" && area.Protocol == "2") || (network == "tcp" && area.Protocol == "1") {
		return nil, errors.New("resource policy does not permit the requested protocol")
	}
	if area.ConnectorType != "" && area.ConnectorType != "native" {
		return nil, errors.New("resource connector transport is not supported")
	}
	id, err := control.UUID()
	if err != nil {
		return nil, err
	}
	pid := os.Getpid()
	body := map[string]any{
		"areaid": area.ID, "set_id": area.SetID, "tenant_id": e.Client.TenantID, "request_id": id,
		"uid": e.Identity.ID, "user_id": e.Identity.UserID, "device_id": e.Identity.DeviceID, "tgt": e.Identity.Ticket, "tgt_2nd": "",
		"protocol": network, "req_url": address, "os_type": "linux", "app_id": "0", "app_name": "", "app_version": "",
		"req_pid": strconv.Itoa(pid), "req_pname": "svpn-cli", "communication_type": 2,
	}
	// Start the relative lifetime before the request, conservatively accounting
	// for response latency instead of extending the server-issued expiry.
	issued := time.Now()
	r, err := e.Client.Call(ctx, "/api/public/clientlogin/apply_st", "", body)
	if err != nil {
		return nil, err
	}
	var response struct {
		RetCode    *int       `json:"retcode"`
		Action     string     `json:"action"`
		ActionCode int        `json:"action_code"`
		ClientIP   string     `json:"clientip"`
		Gateways   [][]string `json:"smartgate_server"`
		STInfo     []struct {
			ST       string `json:"st"`
			URL      string `json:"url"`
			Begin    string `json:"valid_begin_offset"`
			End      string `json:"valid_end_offset"`
			MaxValid int    `json:"max_valid"`
		} `json:"stinfo"`
	}
	data, _ := json.Marshal(r)
	if json.Unmarshal(data, &response) != nil || response.RetCode == nil || *response.RetCode != 0 || response.ActionCode != 0 || (response.Action != "" && response.Action != "proxy") || len(response.STInfo) != 1 {
		return nil, errors.New("resource request did not issue one supported proxy grant")
	}
	grant := response.STInfo[0]
	begin, err := strconv.ParseInt(grant.Begin, 10, 64)
	if err != nil || begin != 0 {
		return nil, errors.New("unsupported ticket start offset")
	}
	end, err := strconv.ParseInt(grant.End, 10, 64)
	if err != nil || end <= 15 || end > 86400 || grant.ST == "" || grant.URL != address || grant.MaxValid < 1 {
		return nil, errors.New("invalid issued ticket lifetime, target or allowance")
	}
	// Never use a gateway absent from the authenticated resource policy.
	allowed := map[string]bool{}
	for _, group := range area.Gateways {
		for _, g := range group {
			allowed[g] = true
		}
	}
	gateway := ""
	for _, group := range response.Gateways {
		for _, g := range group {
			if allowed[g] {
				gateway = g
				break
			}
		}
		if gateway != "" {
			break
		}
	}
	if gateway == "" {
		return nil, errors.New("ticket has no gateway matching resource policy")
	}
	allowance := grant.MaxValid
	if allowance > 10000 {
		allowance = 10000
	}
	session := &native.Session{Version: 1, Gateway: "https://" + gateway, TLSMode: e.GatewayTLS, HeaderProfile: e.Client.Profile, CertificateSHA256: e.CertificateSHA256, CAFile: e.CAFile, ExpiresAt: issued.Add(time.Duration(end)*time.Second - 5*time.Second), Resources: []native.Resource{{
		Address: address, Machine: e.Client.Machine, MaxConnections: allowance,
		// These App fields are gateway compatibility metadata, not
		// process identity. The actual requesting process above is this CLI.
		Ticket: native.TicketJSON{UserName: e.Identity.UserID, DeviceID: e.Identity.DeviceID, ST: grant.ST, AppID: "0", AppName: "smartVPN", AppVersion: "3.0.5.0", ReqUrl: address, ProcName: "svpn-cli", PID: pid,
			// ServiceId is the matched area ID. Omitting it causes HTTP 403 even
			// when apply_st successfully issues a valid ST.
			ServiceId: area.ID, TenantId: e.Client.TenantID, ClientIp: response.ClientIP, Protocol: network},
	}}}
	if err := session.Validate(time.Now()); err != nil {
		return nil, err
	}
	return session, nil
}

func (e *Engine) DialContext(ctx context.Context, area *policy.Area, address string) (net.Conn, error) {
	return e.dialNetwork(ctx, "tcp", area, address)
}

func (e *Engine) DialUDPContext(ctx context.Context, area *policy.Area, address string) (net.Conn, error) {
	return e.dialNetwork(ctx, "udp", area, address)
}

func (e *Engine) dialNetwork(ctx context.Context, network string, area *policy.Area, address string) (net.Conn, error) {
	if area == nil {
		return nil, errors.New("resource rule required")
	}
	// A refreshed policy can retain an ID while changing its gateway route.
	// New connections must obtain a grant for that updated route.
	routeJSON, err := json.Marshal(area)
	if err != nil {
		return nil, errors.New("invalid resource route")
	}
	key := fmt.Sprintf("%s/%x/%s", network, sha256.Sum256(routeJSON), address)
	for {
		e.mu.Lock()
		entry := e.cache[key]
		now := time.Now()
		if entry != nil && entry.ready != nil {
			ready := entry.ready
			e.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ready:
				continue
			}
		}
		if entry != nil && entry.expires.After(now.Add(15*time.Second)) && entry.dialer != nil && entry.remaining > 0 {
			entry.remaining--
			d := entry.dialer
			e.mu.Unlock()
			return d.DialContext(ctx, network, address)
		}
		if entry != nil && entry.err != nil && entry.expires.After(now) {
			err := entry.err
			e.mu.Unlock()
			return nil, err
		}
		if entry == nil && len(e.cache) >= 256 {
			oldest := ""
			var deadline time.Time
			for k, v := range e.cache {
				if v.ready == nil && (oldest == "" || v.expires.Before(deadline)) {
					oldest = k
					deadline = v.expires
				}
			}
			if oldest == "" {
				e.mu.Unlock()
				return nil, errors.New("too many outstanding resource requests")
			}
			delete(e.cache, oldest)
		}
		entry = &cachedGrant{ready: make(chan struct{})}
		e.cache[key] = entry
		e.mu.Unlock()
		session, err := e.IssueNetwork(ctx, network, address, area)
		var dialer *native.Dialer
		if err == nil {
			dialer, err = native.NewDialer(session)
		}
		e.mu.Lock()
		if err != nil {
			entry.err = fmt.Errorf("resource grant unavailable: %w", err)
			entry.expires = time.Now().Add(5 * time.Second)
		} else {
			entry.dialer = dialer
			entry.remaining = session.Resources[0].MaxConnections
			entry.expires = session.ExpiresAt
		}
		close(entry.ready)
		entry.ready = nil
		e.mu.Unlock()
		if err != nil {
			return nil, entry.err
		}
	}
}
