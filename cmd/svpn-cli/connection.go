package main

import (
	"context"
	"flag"

	"github.com/howtomakeaname/svpn-cli/internal/native"
	"github.com/howtomakeaname/svpn-cli/internal/proxy"
	"github.com/howtomakeaname/svpn-cli/internal/routing"
)

// All streaming commands share policy, ticket, header and trust behavior.
// This prevents forwarding commands from accidentally bypassing VPN policy.
type connectionOptions struct {
	state, session, mode, pin, ca string
	headers                       headerFlags
}

func (o *connectionOptions) bind(f *flag.FlagSet) {
	o.headers = addHeaderFlags(f)
	f.StringVar(&o.state, "state", "", "private login state; enables automatic policy and ticket acquisition")
	f.StringVar(&o.session, "session", "", "private JSON file with already-issued resource tickets")
	f.StringVar(&o.mode, "mode", "vpn-only", "routing with --state: vpn-only or auto")
	f.StringVar(&o.pin, "certificate-sha256", "", "explicit gateway leaf certificate trust anchor; verify independently")
	f.StringVar(&o.ca, "gateway-ca", "", "additional gateway CA PEM file")
}

func (o connectionOptions) validate() error {
	if (o.session == "") == (o.state == "") {
		return usageError("provide exactly one of --state or --session")
	}
	if o.mode != "vpn-only" && o.mode != "auto" {
		return usageError("--mode must be vpn-only or auto")
	}
	if o.session != "" && (o.mode != "vpn-only" || o.pin != "" || o.ca != "") {
		return usageError("mode and gateway trust flags require --state; session files contain their own trust settings")
	}
	return nil
}

func (o connectionOptions) open(ctx context.Context) (proxy.DialFunc, func(), error) {
	noop := func() {}
	if o.state != "" {
		e, err := loginEngine(o.state, o.pin, o.ca)
		if err != nil {
			return nil, noop, err
		}
		cleanup := e.Client.HTTP.CloseIdleConnections
		e.Client.Profile, err = o.headers.apply(e.Client.Profile)
		if err != nil {
			cleanup()
			return nil, noop, err
		}
		router, err := routing.New(o.mode, e.FetchPolicy, e.DialContext)
		if err == nil {
			_, err = router.Policy(ctx)
		}
		if err != nil {
			cleanup()
			return nil, noop, remoteFailure(err)
		}
		return router.DialContext, cleanup, nil
	}
	session, err := loadSession(o.session)
	if err != nil {
		return nil, noop, err
	}
	session.HeaderProfile, err = o.headers.apply(session.HeaderProfile)
	if err != nil {
		return nil, noop, err
	}
	dialer, err := native.NewDialer(session)
	if err != nil {
		return nil, noop, err
	}
	return dialer.DialContext, noop, nil
}
