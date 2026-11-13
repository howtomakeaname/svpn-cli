package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/howtomakeaname/svpn-cli/internal/control"
	"github.com/howtomakeaname/svpn-cli/internal/headers"
	"github.com/howtomakeaname/svpn-cli/internal/privatefs"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type authState struct {
	Version       int                        `json:"version"`
	Origin        string                     `json:"origin"`
	GUID          string                     `json:"guid"`
	Machine       string                     `json:"machine"`
	MID           string                     `json:"mid,omitempty"`
	Organization  control.Organization       `json:"organization"`
	CreatedAt     time.Time                  `json:"created_at"`
	Registration  map[string]json.RawMessage `json:"registration,omitempty"`
	PendingSSO    *pendingSSO                `json:"pending_sso,omitempty"`
	Login         map[string]json.RawMessage `json:"login,omitempty"`
	Exchange      map[string]json.RawMessage `json:"exchange,omitempty"`
	Status        map[string]json.RawMessage `json:"status,omitempty"`
	HeaderProfile headers.Profile            `json:"header_profile,omitempty"`
}

func writeAuth(path string, s *authState) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := privatefs.CreateTemp(dir, ".auth-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func readAuth(path string) (authState, error) {
	s, err := readAuthFile(path)
	if err != nil && !os.IsNotExist(err) && !os.IsPermission(err) {
		return s, &cliError{Code: "INVALID_AUTH_STATE", Message: "Cannot read a valid private authentication state file.", exit: 4, cause: err}
	}
	return s, err
}

func readAuthFile(path string) (authState, error) {
	var s authState
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return s, err
	}
	if privatefs.Check(f) != nil || info.Size() > 2<<20 {
		return s, errors.New("auth state must be a private regular file smaller than 2 MiB")
	}
	decoder := json.NewDecoder(io.LimitReader(f, (2<<20)+1))
	if err := decoder.Decode(&s); err != nil {
		return s, errors.New("invalid auth state JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return s, errors.New("auth state must contain exactly one JSON value")
	}
	if s.Version != 1 {
		return s, errors.New("unsupported auth state")
	}
	return s, nil
}

func (a *application) runAuth(args []string) error {
	group := a.newFlagSet("auth")
	if err := a.parseFlags(group, args); err != nil {
		return err
	}
	args = group.Args()
	if len(args) == 0 {
		return a.showHelp(group)
	}
	if len(args) > 0 && args[0] == "sso" {
		return a.runSSO(args[1:])
	}
	if len(args) > 0 && args[0] == "finish" {
		return a.runSSOFinish(args[1:])
	}
	if len(args) > 0 && args[0] == "exchange" {
		return a.runExchange(args[1:])
	}
	if len(args) > 0 && args[0] == "status" {
		return a.runAuthStatus(args[1:])
	}
	if args[0] == "inspect" {
		return a.runAuthInspect(args[1:])
	}
	if args[0] != "init" {
		return usageError("unknown auth subcommand; use svpn-cli auth --help")
	}
	f := a.newFlagSet("auth init")
	headerOptions := addHeaderFlags(f)
	path := f.String("state", "private/auth.json", "private device state path")
	pin := f.String("pin", "", "organization PIN (required for first initialization)")
	machine := f.String("machine", "", "device display name (saved in device state)")
	origin := f.String("origin", "https://scs.gateway.tencent.com", "HTTPS control origin")
	if err := a.parseFlags(f, args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return usageError("unexpected positional arguments")
	}
	state, err := readAuth(*path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if *pin == "" {
			return usageError("--pin is required for first initialization")
		}
		if _, err := control.NewClient(*origin); err != nil {
			return usageError("--origin must be an HTTPS origin without credentials, query or fragment")
		}
		guid, err := control.UUID()
		if err != nil {
			return err
		}
		state = authState{Version: 1, Origin: *origin, GUID: guid, CreatedAt: time.Now()}
	}
	state.HeaderProfile, err = headerOptions.apply(state.HeaderProfile)
	if err != nil {
		return err
	}
	if *machine != "" {
		if len(*machine) > 63 || strings.ContainsAny(*machine, "\r\n\x00") {
			return usageError("device display name must be 1-63 bytes without control separators")
		}
		state.Machine = *machine
	}
	if state.Machine == "" {
		state.Machine = "MacBook-Pro"
	}
	if state.Organization.TenantID == "" && *pin == "" {
		return usageError("--pin is required for organization discovery")
	}
	if err := writeAuth(*path, &state); err != nil {
		return err
	}
	client, err := control.NewClient(state.Origin)
	if err != nil {
		return err
	}
	client.GUID = control.DeviceGUID(state.GUID)
	client.Machine = state.Machine
	client.MID = state.MID
	client.Profile = state.HeaderProfile
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if state.Organization.TenantID == "" {
		org, err := client.QueryOrganization(ctx, *pin)
		if err != nil {
			return remoteFailure(err)
		}
		state.Organization = org
		if err := writeAuth(*path, &state); err != nil {
			return err
		}
	}
	client.TenantID = state.Organization.TenantID
	if state.MID == "" {
		result, err := client.Register(ctx)
		// Preserve the exact response privately before interpreting its shape.
		if result != nil {
			state.Registration = result
			if saveErr := writeAuth(*path, &state); saveErr != nil {
				return saveErr
			}
		}
		if err != nil {
			return remoteFailure(err)
		}
		for _, key := range []string{"", "Reply", "Data"} {
			var values map[string]json.RawMessage
			if key == "" {
				values = result
			} else if json.Unmarshal(result[key], &values) != nil {
				continue
			}
			for _, field := range []string{"Mid", "MID", "mid"} {
				if raw, ok := values[field]; ok {
					if json.Unmarshal(raw, &state.MID) != nil {
						var n json.Number
						if json.Unmarshal(raw, &n) == nil {
							state.MID = n.String()
						}
					}
				}
			}
		}
		if state.MID == "" {
			return errors.New("registration response saved privately; MID field needs verification before generating a login URL")
		}
		if err := writeAuth(*path, &state); err != nil {
			return err
		}
	}
	u, err := url.Parse(state.Origin + "/akpage/login")
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("mid", state.MID)
	q.Set("hl", "zh-CN")
	q.Set("os", "linux")
	q.Set("Tenant-Id", state.Organization.TenantID)
	q.Set("theme", "ioa-saas-new")
	u.RawQuery = q.Encode()
	return a.result("auth init", fmt.Sprintf("Organization: %s\nDevice name: %s\nDevice state: %s\nOfficial login page (regular browser sessions differ from device sessions):\n%s\nFor a CLI-bound CAS flow, run: svpn-cli auth sso --state %s", state.Organization.Company, state.Machine, *path, u.String(), *path), map[string]any{
		"state_file": *path, "registered": true,
		"next_action": nextAction{Kind: "run_command", Argv: []string{"svpn-cli", "--json", "auth", "sso", "--state", *path}},
	})
}
