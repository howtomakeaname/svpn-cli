package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/howtomakeaname/svpn-cli/internal/control"
)

func rawFields(value any) map[string]json.RawMessage {
	data, _ := json.Marshal(value)
	var result map[string]json.RawMessage
	json.Unmarshal(data, &result)
	return result
}

func TestInspectLocalStagesAndRedaction(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "auth.json")
	s := &authState{Version: 1, Origin: "https://must-not-be-contacted.example", GUID: "secret-guid"}
	assertStage := func(state *authState, stage, action string) {
		t.Helper()
		if state != nil {
			if err := writeAuth(path, state); err != nil {
				t.Fatal(err)
			}
		}
		code, out, errOut := invoke("--json", "auth", "inspect", "--state", path)
		if code != 0 || errOut != "" || !decodeResponse(t, out).OK || strings.Contains(out, "secret-") {
			t.Fatal("inspect failed or leaked state")
		}
		var r struct {
			Data authSummary `json:"data"`
		}
		json.Unmarshal([]byte(out), &r)
		if r.Data.Stage != stage || r.Data.NextAction.Kind != action || r.Data.ServerValidated || r.Data.CredentialValidity != "unknown" {
			t.Fatalf("unexpected summary: %+v", r.Data)
		}
	}
	assertStage(nil, "uninitialized", "run_command")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("read-only inspection created state")
	}
	assertStage(s, "initialized", "run_command")
	s.MID = "secret-device"
	assertStage(s, "registered", "run_command")
	s.PendingSSO = &pendingSSO{State: "secret-state", ExpiresAt: now.Add(time.Minute)}
	assertStage(s, "awaiting_browser", "browser_login")
	s.PendingSSO.ExpiresAt = now.Add(-time.Minute)
	assertStage(s, "sso_expired", "run_command")
	s.PendingSSO = nil
	s.Login = rawFields(map[string]any{"need_mfa": true, "ticket": "secret-ticket"})
	assertStage(s, "challenge_required", "human_authentication")
	s.Login = rawFields(map[string]any{"uid": "secret-user", "ticket": "secret-ticket", "mid": s.MID, "domain_id": "secret-domain", "device_type": "Linux", "ticket_type": 2})
	assertStage(s, "login_saved", "run_command")
	s.Exchange = rawFields(map[string]any{"data": map[string]any{"ID": 123, "UserID": "secret-user", "DeviceID": s.MID, "Ticket": "secret-tgt", "TicketType": 0}})
	assertStage(s, "exchanged", "run_command")
	// A nonempty response map is insufficient: identity must bind to this device.
	s.Exchange = rawFields(map[string]any{"data": map[string]any{"ID": 123, "UserID": "secret-user", "DeviceID": "wrong-device", "Ticket": "secret-tgt", "TicketType": 0}})
	assertStage(s, "login_saved", "run_command")
	if err := writePrivateJSON(path, map[string]any{"version": 999}); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := invoke("--json", "auth", "inspect", "--state", path)
	if code != 4 || out != "" || decodeResponse(t, errOut).Error.Code != "INVALID_AUTH_STATE" {
		t.Fatal("invalid state was treated as an uninitialized login")
	}
}

func TestFailedCallbackConsumesPendingAndClearsOldCredentials(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	// The untrusted TLS endpoint fails before a login response. This models the
	// unknown-outcome case without submitting credentials to an external service.
	s := &authState{Version: 1, Origin: server.URL, MID: "secret-device", GUID: "secret-guid"}
	s.Organization = control.Organization{TenantID: "123"}
	s.PendingSSO = &pendingSSO{State: "secret-state", RedirectURI: server.URL + "/akpage/sso/redirect?Tenant-Id=123&state=secret-state", ExpiresAt: time.Now().Add(time.Minute)}
	s.Login, s.Exchange, s.Status = rawFields(map[string]string{"ticket": "secret-old"}), rawFields(map[string]string{"ticket": "secret-old"}), rawFields(map[string]string{"ticket": "secret-old"})
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := writeAuth(path, s); err != nil {
		t.Fatal(err)
	}
	callback := filepath.Join(t.TempDir(), "callback.txt")
	// Reuse the private-file writer for consistent ACLs on Windows as well.
	if err := writePrivateJSON(callback, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(callback, []byte(s.PendingSSO.RedirectURI+"&ticket=secret-callback"), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := invoke("--json", "auth", "finish", "--state", path, "--callback-file", callback)
	if code != 5 || out != "" || decodeResponse(t, errOut).Error.Code != "REMOTE_REQUEST_FAILED" || strings.Contains(errOut, "secret-") {
		t.Fatalf("unexpected failed callback outcome: %d %s", code, errOut)
	}
	saved, err := readAuth(path)
	if err != nil || saved.PendingSSO != nil || saved.Login != nil || saved.Exchange != nil || saved.Status != nil {
		t.Fatal("failed login retained stale credentials or replayable state")
	}
	code, _, errOut = invoke("--json", "auth", "finish", "--state", path, "--callback-file", callback)
	if code != 3 || decodeResponse(t, errOut).Error.Code != "AUTH_REQUIRED" {
		t.Fatal("callback replay was not rejected locally")
	}
}
