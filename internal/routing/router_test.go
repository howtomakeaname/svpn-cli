package routing

import (
	"context"
	"errors"
	"github.com/howtomakeaname/svpn-cli/internal/policy"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(`{"RetCode":0,"BusinessList":[{"BusinessId":143,"Data":{"Configs":[{"Details":{"switch":"1","accessiblearea":[{"areaid":"campus","type":"ip","connaddr":"172.16.0.0/12","filterport":"1","connport":"22","protocol":"2"},{"areaid":"domain","type":"domain","connaddr":"*.campus.example","filterport":"1","connport":"443","protocol":"2"}]}}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRoutingNeverFallsBackAfterVPNOrPolicyDenial(t *testing.T) {
	for _, mode := range []string{"auto", "vpn-only"} {
		t.Run(mode, func(t *testing.T) {
			p := testPolicy(t)
			direct, vpn := 0, 0
			vpnDenied := errors.New("gateway denied")
			r, _ := New(mode, func(context.Context) (*policy.Policy, error) { return p, nil }, func(_ context.Context, a *policy.Area, target string) (net.Conn, error) { vpn++; return nil, vpnDenied })
			r.Direct = func(context.Context, string, string) (net.Conn, error) { direct++; return nil, nil }
			r.Lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("172.16.1.2")}, nil
			}
			if _, err := r.DialContext(context.Background(), "tcp", "172.16.1.2:22"); !errors.Is(err, vpnDenied) {
				t.Fatal(err)
			}
			if _, err := r.DialContext(context.Background(), "tcp", "172.16.1.2:23"); err == nil {
				t.Fatal("protected disallowed port accepted")
			}
			if _, err := r.DialContext(context.Background(), "tcp", "a.campus.example:443"); !errors.Is(err, vpnDenied) {
				t.Fatal(err)
			}
			if _, err := r.DialContext(context.Background(), "tcp", "unlisted.example:22"); !errors.Is(err, vpnDenied) {
				t.Fatal("mixed DNS results bypassed protected address", err)
			}
			if direct != 0 || vpn != 3 {
				t.Fatalf("unexpected direct=%d vpn=%d", direct, vpn)
			}
			_, err := r.DialContext(context.Background(), "tcp", "192.0.2.1:443")
			if mode == "auto" {
				if err != nil || direct != 1 {
					t.Fatal("auto did not direct unmatched traffic")
				}
			} else if err == nil || direct != 0 {
				t.Fatal("vpn-only leaked unmatched traffic")
			}
			r.mu.Lock()
			r.expires = time.Time{}
			r.mu.Unlock()
			r.Fetch = func(context.Context) (*policy.Policy, error) { return nil, errors.New("offline") }
			before := direct
			if _, err := r.DialContext(context.Background(), "tcp", "192.0.2.1:443"); err == nil || before != direct {
				t.Fatal("stale/unavailable policy allowed direct dialing")
			}
		})
	}
}

func TestUDPRoutingDoesNotReuseTCPOrFallBackForProtectedHosts(t *testing.T) {
	p := testPolicy(t)
	for _, mode := range []string{"auto", "vpn-only"} {
		t.Run(mode, func(t *testing.T) {
			tcp, udp, direct := 0, 0, 0
			r, _ := New(mode, func(context.Context) (*policy.Policy, error) { return p, nil }, func(context.Context, *policy.Area, string) (net.Conn, error) { tcp++; return nil, nil })
			r.UDP = func(context.Context, *policy.Area, string) (net.Conn, error) {
				udp++
				return nil, errors.New("UDP denied")
			}
			r.Direct = func(context.Context, string, string) (net.Conn, error) { direct++; return nil, nil }
			r.Lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("172.16.1.2")}, nil
			}
			for _, target := range []string{"172.16.1.2:22", "a.campus.example:443", "unlisted.example:22"} {
				if _, err := r.DialContext(context.Background(), "udp", target); err == nil {
					t.Fatal("TCP-only resource accepted UDP")
				}
			}
			if tcp != 0 || udp != 0 || direct != 0 {
				t.Fatal("protocol denial contacted a transport")
			}
			// The same address may be explicitly enabled for both protocols.
			p.Areas[0].Protocol = "3"
			if _, err := r.DialContext(context.Background(), "udp", "172.16.1.2:22"); err == nil {
				t.Fatal("UDP denial ignored")
			}
			if tcp != 0 || udp != 1 || direct != 0 {
				t.Fatal("UDP failure reused TCP or direct transport")
			}
			p.Areas[0].Protocol = "2"
		})
	}
}

func TestPolicyRefreshCoalescesAndDomainPreservesRemoteDNS(t *testing.T) {
	p := testPolicy(t)
	var calls atomic.Int32
	gate := make(chan struct{})
	r, _ := New("auto", func(context.Context) (*policy.Policy, error) { calls.Add(1); <-gate; return p, nil }, func(_ context.Context, a *policy.Area, target string) (net.Conn, error) {
		if target != "a.campus.example:443" {
			t.Errorf("lost original domain: %s", target)
		}
		return nil, nil
	})
	r.Lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("protected domain leaked to local DNS")
		return nil, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.DialContext(context.Background(), "tcp", "a.campus.example:443"); err != nil {
				t.Error(err)
			}
		}()
	}
	close(gate)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("fetched policy %d times", calls.Load())
	}
}
