package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"github.com/howtomakeaname/svpn-cli/internal/control"
	"github.com/howtomakeaname/svpn-cli/internal/privatefs"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

type pendingSSO struct {
	State       string    `json:"state"`
	Domain      string    `json:"domain"`
	ConfigID    string    `json:"config_id"`
	RedirectURI string    `json:"redirect_uri"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func deviceClient(s *authState) (*control.Client, error) {
	if s.MID == "" {
		return nil, authRequired("run auth init to register this device first")
	}
	c, err := control.NewClient(s.Origin)
	if err != nil {
		return nil, err
	}
	c.GUID, c.MID, c.TenantID, c.Machine = control.DeviceGUID(s.GUID), s.MID, s.Organization.TenantID, s.Machine
	if err := s.HeaderProfile.Validate(); err != nil {
		return nil, err
	}
	c.Profile = s.HeaderProfile
	return c, nil
}

func (a *application) runSSO(args []string) error {
	f := a.newFlagSet("auth sso")
	path := f.String("state", "private/auth.json", "private device state")
	domain := f.String("domain", "", "authentication domain ID")
	if err := a.parseFlags(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return usageError("unexpected positional arguments")
	}
	s, err := readAuth(*path)
	if err != nil {
		return err
	}
	c, err := deviceClient(&s)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	body := map[string]any{"tenantId": c.TenantID, "platform": "Linux"}
	r, err := c.Authkeeper(ctx, "domains", body)
	if err != nil {
		return remoteFailure(err)
	}
	var domains []struct {
		ID      string   `json:"domain_id"`
		Name    string   `json:"domain_name"`
		Configs []string `json:"config_ids"`
	}
	if err := json.Unmarshal(r["domains"], &domains); err != nil || len(domains) == 0 {
		return errors.New("no authentication domains returned")
	}
	if *domain == "" && len(domains) == 1 {
		*domain = domains[0].ID
	}
	var configs []string
	for _, item := range domains {
		if item.ID == *domain {
			configs = item.Configs
		}
	}
	if len(configs) == 0 {
		choices := make([]map[string]string, 0, len(domains))
		for _, item := range domains {
			choices = append(choices, map[string]string{"id": item.ID, "name": item.Name})
		}
		return &cliError{Code: "DOMAIN_SELECTION_REQUIRED", Message: "Select an authentication domain with --domain.", exit: 3,
			Details: map[string]any{"domains": choices}, NextAction: &nextAction{Kind: "choose_domain"}}
	}
	body["domain"], body["config_ids"], body["stage"] = *domain, configs, "login"
	r, err = c.Authkeeper(ctx, "auth-configs", body)
	if err != nil {
		return remoteFailure(err)
	}
	var sources []struct {
		ID     string `json:"id"`
		Type   string `json:"type"`
		Config struct {
			URL string `json:"url"`
		} `json:"config"`
	}
	if json.Unmarshal(r["configs"], &sources) != nil {
		return errors.New("invalid authentication configuration")
	}
	var sourceID, template string
	for _, source := range sources {
		if source.Type == "CAS" {
			if sourceID != "" {
				return &cliError{Code: "UNSUPPORTED_AUTH", Message: "Multiple CAS sources are not supported.", exit: 3}
			}
			sourceID, template = source.ID, source.Config.URL
		}
	}
	if sourceID == "" || !strings.Contains(template, "${uri}") {
		return &cliError{Code: "UNSUPPORTED_AUTH", Message: "This authentication source is not supported (CAS required).", exit: 3}
	}
	nonce, err := control.UUID()
	if err != nil {
		return err
	}
	nonce = strings.ReplaceAll(nonce, "-", "")
	// CAS returns its ticket to this exact service URI. Keep our random state in
	// the service URI as well as the provider's state parameter.
	uri := c.Origin + "/akpage/sso/redirect?" + url.Values{"state": {nonce}, "Tenant-Id": {c.TenantID}}.Encode()
	link := strings.ReplaceAll(strings.ReplaceAll(template, "${uri}", url.QueryEscape(uri)), "${state}", url.QueryEscape(nonce))
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("SSO provider URL must use HTTPS")
	}
	s.PendingSSO = &pendingSSO{State: nonce, Domain: *domain, ConfigID: sourceID, RedirectURI: uri, ExpiresAt: time.Now().Add(10 * time.Minute)}
	if err := writeAuth(*path, &s); err != nil {
		return err
	}
	return a.result("auth sso", "Open in your browser (valid 10 minutes):\n"+u.String()+"\n\nAfter the redirect, cancel any request to open iOA. Import the HTTPS callback using auth finish --callback-file or the hidden terminal prompt. Do not post it in chat.", map[string]any{
		"state_file": *path, "login_url": u.String(), "expires_at": s.PendingSSO.ExpiresAt,
		"next_action": nextAction{Kind: "browser_login", Message: "A user must complete browser login/MFA, then supply the HTTPS callback via a private file or explicit stdin."},
	})
}

func parseSSOCallback(raw string, pending *pendingSSO, now time.Time) (string, error) {
	if pending == nil || !now.Before(pending.ExpiresAt) {
		return "", errors.New("no pending SSO request or request expired; run auth sso again")
	}
	if len(raw) > 8192 {
		return "", errors.New("callback URL too large")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	expected, parseErr := url.Parse(pending.RedirectURI)
	if err != nil || parseErr != nil || u.User != nil || u.Fragment != "" || u.Scheme != "https" || u.Host != expected.Host || u.Path != expected.Path {
		return "", errors.New("callback must be the expected HTTPS SSO redirect URL")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(pending.State)) != 1 {
		return "", errors.New("SSO state mismatch")
	}
	if q.Get("Tenant-Id") != expected.Query().Get("Tenant-Id") || len(q["Tenant-Id"]) != 1 {
		return "", errors.New("callback tenant mismatch")
	}
	if q.Get("error") != "" {
		return "", errors.New("SSO provider returned an authentication error")
	}
	values := append(q["ticket"], q["code"]...)
	if len(values) != 1 || values[0] == "" || len(values[0]) > 4096 {
		return "", errors.New("callback must contain exactly one nonempty ticket or code")
	}
	return values[0], nil
}

func (a *application) runSSOFinish(args []string) error {
	f := a.newFlagSet("auth finish")
	path := f.String("state", "private/auth.json", "private device state")
	callbackFile := f.String("callback-file", "", "0600 file containing full callback URL (otherwise hidden terminal prompt)")
	callbackStdin := f.Bool("callback-stdin", false, "read callback URL from stdin until EOF; never echo it")
	if err := a.parseFlags(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return usageError("unexpected positional arguments")
	}
	if *callbackFile != "" && *callbackStdin {
		return usageError("provide only one of --callback-file and --callback-stdin")
	}
	if (a.json || a.nonInteractive) && *callbackFile == "" && !*callbackStdin {
		return &cliError{Code: "INTERACTION_REQUIRED", Message: "Supply the HTTPS SSO callback using --callback-file or --callback-stdin; interactive input is disabled.", exit: 3,
			NextAction: &nextAction{Kind: "supply_callback", Message: "Complete browser login/MFA, then provide the callback through a private file or stdin."}}
	}
	s, err := readAuth(*path)
	if err != nil {
		return err
	}
	c, err := deviceClient(&s)
	if err != nil {
		return err
	}
	if s.PendingSSO == nil || !time.Now().Before(s.PendingSSO.ExpiresAt) {
		return authRequired("no pending SSO request or request expired; run auth sso again")
	}
	var raw []byte
	if *callbackFile != "" {
		file, err := os.Open(*callbackFile)
		if err != nil {
			return err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || privatefs.Check(file) != nil || info.Size() > 8192 {
			return &cliError{Code: "INVALID_CALLBACK_FILE", Message: "Callback file must be a private regular file smaller than 8 KiB.", exit: 4}
		}
		raw, err = io.ReadAll(io.LimitReader(file, 8193))
		if err != nil {
			return errors.New("cannot read callback file")
		}
	} else if *callbackStdin {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, 8193))
		if err != nil || len(raw) > 8192 {
			return usageError("cannot read callback from stdin or input exceeds 8 KiB")
		}
	} else {
		raw, err = readCallbackInput()
		if err != nil {
			return err
		}
	}
	code, err := parseSSOCallback(string(raw), s.PendingSSO, time.Now())
	if err != nil {
		return &cliError{Code: "INVALID_CALLBACK", Message: err.Error(), exit: 2}
	}
	pending := *s.PendingSSO
	// One callback attempt per random state; do not silently reuse CAS tickets.
	s.PendingSSO = nil
	// A new callback belongs to a new login attempt. Old credentials must not
	// appear ready if this attempt fails or requires another challenge.
	s.Login, s.Exchange, s.Status = nil, nil, nil
	if err := writeAuth(*path, &s); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, callErr := c.Authkeeper(ctx, "login", map[string]any{
		"tenantId": c.TenantID, "domain": pending.Domain, "platform": "Linux",
		"config_type": "CAS", "config_id": pending.ConfigID, "config_method": "default",
		"code": code, "redirect_uri": pending.RedirectURI,
	})
	if result != nil {
		s.Login = result
		if err := writeAuth(*path, &s); err != nil {
			return err
		}
	}
	if callErr != nil {
		return remoteFailure(callErr)
	}
	var mfa bool
	json.Unmarshal(result["need_mfa"], &mfa)
	if mfa {
		return &cliError{Code: "INTERACTION_REQUIRED", Message: "An additional authentication challenge is required; the response was saved privately. This challenge is not supported yet.", exit: 3,
			NextAction: &nextAction{Kind: "human_authentication"}}
	}
	return a.result("auth finish", "SSO accepted for this device; login response saved privately. Run auth exchange next.", map[string]any{"state_file": *path, "response_saved": true,
		"next_action": nextAction{Kind: "run_command", Argv: []string{"svpn-cli", "--json", "auth", "exchange", "--state", *path}}})
}
