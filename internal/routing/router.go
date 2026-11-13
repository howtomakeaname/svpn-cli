// Package routing combines policy decisions with VPN or direct TCP dialing.
package routing

import (
	"context"
	"errors"
	"github.com/howtomakeaname/svpn-cli/internal/native"
	"github.com/howtomakeaname/svpn-cli/internal/policy"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type Router struct {
	Mode       string
	Fetch      func(context.Context) (*policy.Policy, error)
	VPN        func(context.Context, *policy.Area, string) (net.Conn, error)
	UDP        func(context.Context, *policy.Area, string) (net.Conn, error)
	Direct     func(context.Context, string, string) (net.Conn, error)
	Lookup     func(context.Context, string, string) ([]netip.Addr, error)
	mu         sync.Mutex
	snapshot   *policy.Policy
	expires    time.Time
	refresh    chan struct{}
	refreshErr error
	retryAt    time.Time
}

func New(mode string, fetch func(context.Context) (*policy.Policy, error), vpn func(context.Context, *policy.Area, string) (net.Conn, error)) (*Router, error) {
	if mode != "auto" && mode != "vpn-only" {
		return nil, errors.New("mode must be auto or vpn-only")
	}
	if fetch == nil || vpn == nil {
		return nil, errors.New("policy fetcher and VPN transport required")
	}
	direct := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	return &Router{Mode: mode, Fetch: fetch, VPN: vpn, Direct: direct.DialContext, Lookup: net.DefaultResolver.LookupNetIP}, nil
}

func (r *Router) Policy(ctx context.Context) (*policy.Policy, error) {
	for {
		r.mu.Lock()
		now := time.Now()
		if r.snapshot != nil && r.expires.After(now) {
			p := r.snapshot
			r.mu.Unlock()
			return p, nil
		}
		if r.refresh != nil {
			ready := r.refresh
			r.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ready:
				continue
			}
		}
		if r.refreshErr != nil && r.retryAt.After(now) {
			err := r.refreshErr
			r.mu.Unlock()
			return nil, err
		}
		r.refresh = make(chan struct{})
		r.mu.Unlock()
		p, err := r.Fetch(ctx)
		if err == nil && p == nil {
			err = errors.New("empty resource policy")
		}
		r.mu.Lock()
		if err == nil {
			r.snapshot = p
			r.expires = time.Now().Add(5 * time.Minute)
			r.refreshErr = nil
		} else {
			r.refreshErr = err
			r.retryAt = time.Now().Add(5 * time.Second)
		}
		close(r.refresh)
		r.refresh = nil
		r.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
}

func (r *Router) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	protocol := "tcp"
	if network == "udp" || network == "udp4" || network == "udp6" {
		protocol = "udp"
	} else if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("unsupported routing protocol")
	}
	vpn := r.VPN
	if protocol == "udp" {
		vpn = r.UDP
	}
	vpnDial := func(ctx context.Context, a *policy.Area, target string) (net.Conn, error) {
		if vpn == nil {
			return nil, errors.New("requested VPN transport is unavailable")
		}
		return vpn(ctx, a, target)
	}
	address, err := native.CanonicalAddress(address)
	if err != nil {
		return nil, err
	}
	host, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portText)
	p, err := r.Policy(ctx)
	if err != nil {
		return nil, errors.New("resource policy unavailable; routing refused")
	}
	area, protected := p.MatchNetwork(protocol, host, port)
	if area != nil {
		return vpnDial(ctx, area, address)
	}
	if protected {
		return nil, errors.New("resource port or protocol is not permitted by policy")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		if r.Mode == "vpn-only" {
			return nil, errors.New("target does not match VPN resource policy")
		}
		return r.Direct(ctx, network, address)
	}
	// Exact/suffix domain rules above need no local DNS. Otherwise resolve once
	// and pin the chosen answer so the direct dial cannot re-resolve/rebind it.
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := r.Lookup(lookupCtx, "ip", host)
	if err != nil {
		return nil, errors.New("target DNS resolution failed")
	}
	blocked := false
	for _, ip := range ips {
		a, deny := p.MatchNetwork(protocol, ip.Unmap().String(), port)
		if a != nil {
			return vpnDial(ctx, a, net.JoinHostPort(ip.Unmap().String(), portText))
		}
		blocked = blocked || deny
	}
	if blocked {
		return nil, errors.New("resolved resource port or protocol is not permitted by policy")
	}
	if r.Mode == "vpn-only" {
		return nil, errors.New("target does not match VPN resource policy")
	}
	if len(ips) == 0 {
		return nil, errors.New("DNS returned no target addresses")
	}
	return r.Direct(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), portText))
}
