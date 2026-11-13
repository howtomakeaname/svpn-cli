package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSSOCallbackBinding(t *testing.T) {
	now := time.Now()
	pending := &pendingSSO{State: "random-state", RedirectURI: "https://control.example/akpage/sso/redirect?Tenant-Id=123&state=random-state", ExpiresAt: now.Add(time.Minute)}
	valid := pending.RedirectURI + "&ticket=secret-ticket"
	if code, err := parseSSOCallback(valid, pending, now); err != nil || code != "secret-ticket" {
		t.Fatalf("valid callback: %v", err)
	}
	for _, invalid := range []string{
		strings.Replace(valid, "https:", "http:", 1),
		strings.Replace(valid, "control.example", "attacker.example", 1),
		strings.Replace(valid, "Tenant-Id=123", "Tenant-Id=456", 1),
		strings.Replace(valid, "state=random-state", "state=other", 1),
		valid + "&state=random-state", valid + "&ticket=second", valid + "&code=second",
		valid + "#ignored", valid + "&error=denied",
	} {
		_, err := parseSSOCallback(invalid, pending, now)
		if err == nil || strings.Contains(err.Error(), "secret-ticket") {
			t.Fatal("invalid callback accepted or secret leaked")
		}
	}
	if _, err := parseSSOCallback(valid, pending, pending.ExpiresAt); err == nil {
		t.Fatal("expired callback accepted")
	}
	if _, err := parseSSOCallback(valid, nil, now); err == nil {
		t.Fatal("unsolicited callback accepted")
	}
	u, _ := url.Parse(valid)
	u.User = url.User("attacker")
	if _, err := parseSSOCallback(u.String(), pending, now); err == nil {
		t.Fatal("callback userinfo accepted")
	}
}

func TestAuthStatePrivacyAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "auth.json")
	s := authState{Version: 1, GUID: "private-seed", Machine: "MacBook-Pro", MID: "test-device"}
	if err := writeAuth(path, &s); err != nil {
		t.Fatal(err)
	}
	read, err := readAuth(path)
	if err != nil || read.GUID != s.GUID || read.Machine != s.Machine {
		t.Fatal("identity not preserved")
	}
	info, _ := os.Stat(path)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("state not private")
	}
	data, _ := json.Marshal(s)
	if err := os.WriteFile(path, append(data, []byte(" {}")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuth(path); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	if runtime.GOOS != "windows" {
		os.Chmod(path, 0644)
		if _, err := readAuth(path); err == nil {
			t.Fatal("public state file accepted")
		}
	}
}
