package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/howtomakeaname/svpn-cli/internal/control"
	"github.com/howtomakeaname/svpn-cli/internal/native"
)

func invoke(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := execute(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func decodeResponse(t *testing.T, text string) response {
	t.Helper()
	var r response
	decoder := json.NewDecoder(strings.NewReader(text))
	if err := decoder.Decode(&r); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if decoder.Decode(new(any)) != io.EOF || r.SchemaVersion != 1 {
		t.Fatal("expected exactly one versioned response")
	}
	return r
}

func TestHelpDiscoveryAndVersion(t *testing.T) {
	for _, spec := range commandSpecs {
		args := append([]string{"--json", "help"}, strings.Fields(spec.Name)...)
		code, out, errOut := invoke(args...)
		if code != 0 || errOut != "" || !decodeResponse(t, out).OK {
			t.Fatalf("help for %s failed", spec.Name)
		}
		var help struct {
			Data struct {
				Command commandSpec `json:"command"`
				Flags   []flagHelp  `json:"flags"`
			} `json:"data"`
		}
		json.Unmarshal([]byte(out), &help)
		if help.Data.Command.Name != spec.Name || len(help.Data.Flags) == 0 {
			t.Fatalf("help omitted command metadata for %s", spec.Name)
		}
	}
	for _, args := range [][]string{{"--json", "--version"}, {"version", "--json"}, {"help", "--json"}, {"--json", "--help"}, {"auth", "--json", "--help"}, {"--json"}} {
		code, out, errOut := invoke(args...)
		if code != 0 || errOut != "" || !decodeResponse(t, out).OK {
			t.Fatalf("discovery failed: %v", args)
		}
	}
	for _, args := range [][]string{{"auth", "--help"}, {"help", "auth", "finish"}, {"serve", "--help"}} {
		code, out, errOut := invoke(args...)
		if code != 0 || !strings.Contains(out, "Usage:") || errOut != "" {
			t.Fatalf("text help failed: %v", args)
		}
	}
}

func TestJSONErrorsAndArgumentValidation(t *testing.T) {
	for _, test := range []struct {
		args []string
		code string
		exit int
	}{
		{[]string{"unknown-secret-ticket"}, "INVALID_ARGUMENT", 2},
		{[]string{"auth", "unknown-secret-ticket"}, "INVALID_ARGUMENT", 2},
		{[]string{"serve", "--max-connections", "secret-value"}, "INVALID_ARGUMENT", 2},
		{[]string{"serve", "--state", "unused", "--mode", "invalid"}, "INVALID_ARGUMENT", 2},
		{[]string{"serve", "--state", "unused", "--http", "0.0.0.0:8080"}, "INVALID_ARGUMENT", 2},
		{[]string{"connect", "--state", "unused", "host", "0"}, "INVALID_ARGUMENT", 2},
		{[]string{"forward", "--state", "unused"}, "INVALID_ARGUMENT", 2},
		{[]string{"forward", "--state", "unused", "--target", "inside.example:22", "--listen", "0.0.0.0:8080"}, "INVALID_ARGUMENT", 2},
		{[]string{"connect", "--state", "unused", "host", "22", "--json"}, "INVALID_ARGUMENT", 2},
		{[]string{"auth", "finish"}, "INTERACTION_REQUIRED", 3},
		{[]string{"auth", "finish", "--callback-file", "unused", "--callback-stdin"}, "INVALID_ARGUMENT", 2},
		{[]string{"check", "--session", filepath.Join(t.TempDir(), "missing")}, "FILE_NOT_FOUND", 4},
	} {
		code, out, errOut := invoke(append([]string{"--json"}, test.args...)...)
		if code != test.exit || out != "" {
			t.Fatalf("unexpected exit/stdout for %v: %d %q", test.args, code, out)
		}
		r := decodeResponse(t, errOut)
		if r.OK || r.Error == nil || r.Error.Code != test.code || r.Error.Retryable || strings.Contains(errOut, "secret-") {
			t.Fatalf("invalid or unsafe error for %v", test.args)
		}
	}
	code, _, errOut := invoke("--non-interactive", "auth", "finish")
	if code != 3 || strings.Contains(errOut, "Paste callback") {
		t.Fatal("non-interactive mode attempted to prompt")
	}
}

func TestJSONResultsNeverExportCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	s := authState{Version: 1, Origin: "https://control.example", GUID: "secret-guid", MID: "secret-mid", Organization: control.Organization{TenantID: "secret-tenant", TenantNonce: "secret-nonce"}}
	if err := writeAuth(path, &s); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := invoke("--json", "auth", "init", "--state", path)
	if code != 0 || errOut != "" || !decodeResponse(t, out).OK || strings.Contains(out, "secret-") {
		t.Fatal("initialization summary failed or leaked private identity")
	}
	for _, err := range []error{errors.New("https://example/?ticket=secret-ticket"), remoteFailure(errors.New("secret-ticket")), &native.GatewayError{Status: 403, Body: "secret-ticket", Headers: http.Header{"Set-Cookie": {"secret-cookie"}}}} {
		data, _ := json.Marshal(classifyError(err))
		if strings.Contains(string(data), "secret-") {
			t.Fatal("error leaked a credential")
		}
	}
	missing := filepath.Join(t.TempDir(), "must-not-be-created.json")
	code, _, _ = invoke("--json", "auth", "init", "--state", missing)
	if code != 2 {
		t.Fatal("missing organization PIN should be a usage error")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("invalid initialization created a state file")
	}
}

func testSession(gateway string) *native.Session {
	return &native.Session{Version: 1, Gateway: gateway, ExpiresAt: time.Now().Add(time.Minute), Resources: []native.Resource{{Address: "inside.example:22", Ticket: native.TicketJSON{ST: "secret-ticket", UserName: "secret-user", DeviceID: "secret-device", Protocol: "tcp"}, MaxConnections: 2}}}
}

func TestCheckReportsLocalValidationOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if err := writePrivateJSON(path, testSession("https://gateway.example")); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := invoke("--json", "check", "--session", path)
	if code != 0 || errOut != "" || !decodeResponse(t, out).OK || !strings.Contains(out, `"connectivity_tested":false`) || strings.Contains(out, "secret-") {
		t.Fatal("session check claimed connectivity or leaked credentials")
	}
}

// A subprocess verifies the real process boundary, stdout bytes and exit code,
// without swapping global stdin or introducing races with the relay goroutine.
func TestCLIHelperProcess(t *testing.T) {
	if os.Getenv("SVPN_CLI_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Exit(execute(os.Args[i+1:], os.Stdout, os.Stderr))
		}
	}
	os.Exit(99)
}

func TestConnectJSONKeepsTCPStreamRaw(t *testing.T) {
	payload := "SSH-2.0-test\r\n\x00\xff\n"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"+payload)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	session := testSession(server.URL)
	pin := sha256.Sum256(server.Certificate().Raw)
	session.CertificateSHA256 = hex.EncodeToString(pin[:])
	path := filepath.Join(t.TempDir(), "session.json")
	if err := writePrivateJSON(path, session); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIHelperProcess$", "--", "--json", "connect", "--session", path, "inside.example", "22")
	cmd.Env = append(os.Environ(), "SVPN_CLI_TEST_PROCESS=1")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil || out.String() != payload || errOut.Len() != 0 {
		t.Fatalf("raw TCP was changed: err=%v stdout=%q stderr=%q", err, out.String(), errOut.String())
	}
}

func TestExplicitCallbackStdinDoesNotEchoInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	s := &authState{Version: 1, Origin: "https://control.example", MID: "secret-device"}
	s.PendingSSO = &pendingSSO{State: "expected-state", RedirectURI: "https://control.example/akpage/sso/redirect?Tenant-Id=123&state=expected-state", ExpiresAt: time.Now().Add(time.Minute)}
	if err := writeAuth(path, s); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIHelperProcess$", "--", "--json", "auth", "finish", "--state", path, "--callback-stdin")
	cmd.Env = append(os.Environ(), "SVPN_CLI_TEST_PROCESS=1")
	cmd.Stdin = strings.NewReader("https://control.example/akpage/sso/redirect?Tenant-Id=123&state=wrong-state&ticket=secret-callback")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || out.Len() != 0 || strings.Contains(errOut.String(), "secret-") || decodeResponse(t, errOut.String()).Error.Code != "INVALID_CALLBACK" {
		t.Fatalf("stdin callback was ignored, echoed or accepted: %v", err)
	}
}
