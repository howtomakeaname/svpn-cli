package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
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
		return nil, errors.New("run auth init to register this device first")
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
		return errors.New("unexpected positional arguments")
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
		return err
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
		for _, item := range domains {
			fmt.Printf("Domain: %s (%s)\n", item.Name, item.ID)
		}
		return errors.New("select an authentication domain with --domain")
	}
	body["domain"], body["config_ids"], body["stage"] = *domain, configs, "login"
	r, err = c.Authkeeper(ctx, "auth-configs", body)
	if err != nil {
		return err
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
				return errors.New("multiple CAS sources are not yet supported")
			}
			sourceID, template = source.ID, source.Config.URL
		}
	}
	if sourceID == "" || !strings.Contains(template, "${uri}") {
		return errors.New("this authentication source is not supported yet (CAS required)")
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
	fmt.Printf("Open in your browser (valid 10 minutes):\n%s\n\nAfter the redirect, cancel any request to open iOA. Import the full callback URL with:\nsvpn-cli auth finish --state %s\nThe terminal prompt hides the callback URL. Do not post it in chat.\n", u.String(), *path)
	return nil
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
	if err := a.parseFlags(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	s, err := readAuth(*path)
	if err != nil {
		return err
	}
	c, err := deviceClient(&s)
	if err != nil {
		return err
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
			return errors.New("callback file must be a private regular file smaller than 8 KiB")
		}
		raw, err = io.ReadAll(io.LimitReader(file, 8193))
		if err != nil {
			return errors.New("cannot read callback file")
		}
	} else {
		raw, err = readCallbackInput()
		if err != nil {
			return err
		}
	}
	code, err := parseSSOCallback(string(raw), s.PendingSSO, time.Now())
	if err != nil {
		return err
	}
	pending := *s.PendingSSO
	// One callback attempt per random state; do not silently reuse CAS tickets.
	s.PendingSSO = nil
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
		return callErr
	}
	var mfa bool
	json.Unmarshal(result["need_mfa"], &mfa)
	if mfa {
		return errors.New("SSO accepted; an additional authkeeper MFA step is required (response saved privately)")
	}
	fmt.Println("SSO accepted for this device; login response saved privately. Native ticket exchange still needs verification.")
	return nil
}
