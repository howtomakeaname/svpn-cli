package engine

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/howtomakeaname/svpn-cli/internal/control"
	"github.com/howtomakeaname/svpn-cli/internal/policy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGrantCarriesResourceBindingAndCoalescesConcurrentRequests(t *testing.T) {
	gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "172.16.1.2:22" {
			t.Error("wrong gateway target")
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\nSSH-2.0-test\r\n")
		rw.Flush()
	}))
	defer gateway.Close()
	address := strings.TrimPrefix(gateway.URL, "https://")
	var grants atomic.Int32
	controlServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants.Add(1)
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid grant request")
		}
		if body["areaid"] != "resource1" || body["req_url"] != "172.16.1.2:22" || body["req_pname"] != "svpn-cli" || body["device_id"] != "own-device" {
			t.Error("resource grant lost request context")
		}
		if _, ok := body["compliance_result"]; ok {
			t.Error("synthetic compliance claim")
		}
		fmt.Fprintf(w, `{"retcode":0,"action":"","action_code":0,"clientip":"192.0.2.1","smartgate_server":[[%q]],"stinfo":[{"st":"issued-test-ticket","url":"172.16.1.2:22","valid_begin_offset":"0","valid_end_offset":"1800","max_valid":20}]}`, address)
	}))
	defer controlServer.Close()
	c, _ := control.NewClient(controlServer.URL)
	c.HTTP = controlServer.Client()
	c.MID = "own-device"
	c.TenantID = "own-tenant"
	e, err := New(c, Identity{ID: 1, UserID: "own-user", DeviceID: c.MID, Ticket: "own-login-ticket"})
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(gateway.Certificate().Raw)
	e.CertificateSHA256 = hex.EncodeToString(pin[:])
	area := &policy.Area{ID: "resource1", SetID: "set1", Gateways: [][]string{{address}}}
	s, err := e.Issue(context.Background(), "172.16.1.2:22", area)
	if err != nil {
		t.Fatal(err)
	}
	if s.Resources[0].Ticket.ServiceId != "resource1" {
		t.Fatal("missing mandatory ServiceId resource binding")
	}
	if s.ExpiresAt.After(time.Now().Add(1796 * time.Second)) {
		t.Fatal("ticket lifetime extended")
	}
	grants.Store(0)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := e.DialContext(context.Background(), area, "172.16.1.2:22")
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil || line != "SSH-2.0-test\r\n" {
				t.Error("lost early SSH banner", err)
			}
		}()
	}
	wg.Wait()
	if grants.Load() != 1 {
		t.Fatalf("concurrent callers requested %d grants", grants.Load())
	}
}

func TestRefuseInvalidOrRedirectedGrant(t *testing.T) {
	for _, variant := range []string{"denied", "redirected", "future", "exhausted", "different-target"} {
		t.Run(variant, func(t *testing.T) {
			response := map[string]any{"retcode": 0, "smartgate_server": [][]string{{"gateway.example:9443"}}, "stinfo": []any{map[string]any{"st": "issued-ticket", "url": "172.16.1.2:22", "valid_begin_offset": "0", "valid_end_offset": "1800", "max_valid": 10}}}
			grant := response["stinfo"].([]any)[0].(map[string]any)
			switch variant {
			case "denied":
				response["retcode"] = 10018
			case "redirected":
				response["smartgate_server"] = [][]string{{"unissued.example:9443"}}
			case "future":
				grant["valid_begin_offset"] = "10"
			case "exhausted":
				grant["max_valid"] = 0
			case "different-target":
				grant["url"] = "172.16.1.3:22"
			}
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				json.NewEncoder(w).Encode(response)
			}))
			defer srv.Close()
			c, _ := control.NewClient(srv.URL)
			c.HTTP = srv.Client()
			c.MID = "own-device"
			e, _ := New(c, Identity{ID: 1, UserID: "own-user", DeviceID: c.MID, Ticket: "own-ticket"})
			if _, err := e.Issue(context.Background(), net.JoinHostPort("172.16.1.2", "22"), &policy.Area{ID: "resource1", SetID: "set1", Gateways: [][]string{{"gateway.example:9443"}}}); err == nil {
				t.Fatal("accepted invalid resource grant")
			}
		})
	}
}
