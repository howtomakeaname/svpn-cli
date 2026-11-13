package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/howtomakeaname/svpn-cli/internal/control"
	"github.com/howtomakeaname/svpn-cli/internal/engine"
)

type authSummary struct {
	StateFile          string     `json:"state_file"`
	StateExists        bool       `json:"state_exists"`
	Stage              string     `json:"stage"`
	Registered         bool       `json:"registered"`
	ServerValidated    bool       `json:"server_validated"`
	CredentialValidity string     `json:"credential_validity"`
	PendingSSOExpires  *time.Time `json:"pending_sso_expires_at,omitempty"`
	NextAction         nextAction `json:"next_action"`
}

// Summarize only allowlisted lifecycle facts. Never marshal the private state,
// upstream response maps, device identifiers or authentication tickets here.
func summarizeAuth(path string, s *authState, now time.Time) authSummary {
	r := authSummary{StateFile: path, CredentialValidity: "unknown", Stage: "uninitialized"}
	command := func(name ...string) nextAction {
		argv := append([]string{"svpn-cli", "--json", "auth"}, name...)
		return nextAction{Kind: "run_command", Argv: append(argv, "--state", path)}
	}
	r.NextAction = command("init")
	r.NextAction.Message = "Supply --pin YOUR_ORGANIZATION_PIN for organization discovery."
	if s == nil {
		return r
	}
	r.StateExists, r.Stage = true, "initialized"
	if s.MID == "" {
		return r
	}
	r.Registered, r.Stage = true, "registered"
	r.NextAction = command("sso")
	if s.PendingSSO != nil {
		r.PendingSSOExpires = &s.PendingSSO.ExpiresAt
		if now.Before(s.PendingSSO.ExpiresAt) {
			r.Stage = "awaiting_browser"
			r.NextAction = nextAction{Kind: "browser_login", Message: "Complete the previously generated browser login/MFA and import the HTTPS callback using auth finish --callback-file or --callback-stdin. Run auth sso to replace a lost URL."}
		} else {
			r.Stage = "sso_expired"
		}
		return r
	}
	var mfa bool
	json.Unmarshal(s.Login["need_mfa"], &mfa)
	if mfa {
		r.Stage = "challenge_required"
		r.NextAction = nextAction{Kind: "human_authentication", Message: "An additional authentication challenge is required and is not supported yet."}
		return r
	}
	var identity engine.Identity
	if json.Unmarshal(s.Exchange["data"], &identity) == nil {
		if _, err := engine.New(&control.Client{MID: s.MID}, identity); err == nil {
			r.Stage = "exchanged"
			r.NextAction = nextAction{Kind: "run_command", Argv: []string{"svpn-cli", "--json", "serve", "--state", path, "--mode", "vpn-only"}, Message: "Local credentials are present; server validity and target connectivity remain untested. Configure gateway trust if required."}
			return r
		}
	}
	var login struct {
		UID        string `json:"uid"`
		Ticket     string `json:"ticket"`
		MID        string `json:"mid"`
		Domain     string `json:"domain_id"`
		DeviceType string `json:"device_type"`
		TicketType int    `json:"ticket_type"`
	}
	data, _ := json.Marshal(s.Login)
	if json.Unmarshal(data, &login) == nil && login.UID != "" && login.Ticket != "" && login.MID == s.MID && login.Domain != "" && login.DeviceType == "Linux" && login.TicketType == 2 {
		r.Stage = "login_saved"
		r.NextAction = command("exchange")
	}
	return r
}

func (a *application) runAuthInspect(args []string) error {
	f := a.newFlagSet("auth inspect")
	path := f.String("state", "private/auth.json", "private device state; missing file reports uninitialized")
	if err := a.parseFlags(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return usageError("unexpected positional arguments")
	}
	s, err := readAuth(*path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var state *authState
	if err == nil {
		state = &s
	}
	r := summarizeAuth(*path, state, time.Now())
	return a.result("auth inspect", fmt.Sprintf("Local stage: %s\nServer validity: unknown (no network request)\nNext action: %s\nCommand arguments: %q\n%s", r.Stage, r.NextAction.Kind, r.NextAction.Argv, r.NextAction.Message), r)
}
