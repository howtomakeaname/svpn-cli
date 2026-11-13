package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/howtomakeaname/svpn-cli/internal/engine"
	"github.com/howtomakeaname/svpn-cli/internal/native"
	"github.com/howtomakeaname/svpn-cli/internal/proxy"
	"github.com/howtomakeaname/svpn-cli/internal/routing"
)

func run(args []string) error {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Println(versionString())
		return nil
	}
	if len(args) > 0 && args[0] == "policy" {
		return runPolicy(args[1:])
	}
	if len(args) > 0 && args[0] == "ticket" {
		return runTicket(args[1:])
	}
	if len(args) > 0 && args[0] == "auth" {
		return runAuth(args[1:])
	}
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Println("svpn-cli: independent experimental iOA TCP client\n\nCommands: auth init|sso|finish|exchange|status, policy, ticket, check, connect, serve\nUse 'svpn-cli COMMAND --help' for options.\n\nconnect/serve --state FILE: fetch policy and obtain resource tickets automatically.\nserve --mode vpn-only: VPN resources only, for mihomo/upstream routing.\nserve --mode auto: policy-selected VPN resources; unmatched destinations direct.\nBoth modes fail closed on protected ports, policy errors and VPN rejection.\nAn explicit --session FILE remains available for transport diagnostics.")
		return nil
	}
	if len(args) == 0 {
		return errors.New("usage: svpn-cli auth init|sso|finish|exchange|status OR connect|serve --state FILE (experimental)")
	}
	command := args[0]
	if command != "check" && command != "connect" && command != "serve" {
		return errors.New("unknown command: use auth, check, connect or serve")
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	headerOptions := addHeaderFlags(flags)
	sessionPath := flags.String("session", "", "private JSON file with already-issued resource tickets")
	statePath := flags.String("state", "", "private device login state; enables automatic policy and resource ticket acquisition")
	mode := flags.String("mode", "vpn-only", "routing mode with --state: vpn-only or auto")
	pin := flags.String("certificate-sha256", "", "explicit gateway leaf certificate trust anchor; verify its fingerprint independently")
	caFile := flags.String("gateway-ca", "", "additional gateway CA PEM file")
	diagnostic := flags.String("diagnostic", "", "connect only: save gateway refusal response to a private JSON file")
	httpAddr := flags.String("http", "127.0.0.1:17890", "HTTP listener; empty disables it")
	socksAddr := flags.String("socks", "127.0.0.1:17891", "SOCKS5 listener; empty disables it")
	limit := flags.Int("max-connections", 128, "maximum concurrent proxy requests")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if (*sessionPath == "") == (*statePath == "") {
		return errors.New("provide exactly one of --state or --session")
	}
	if command == "check" {
		if flags.NArg() != 0 || *sessionPath == "" {
			return errors.New("check requires --session and no positional arguments")
		}
		session, err := native.LoadSession(*sessionPath)
		if err != nil {
			return err
		}
		fmt.Printf("Session format valid: %d resources; expires %s. Gateway connectivity and authentication have NOT been tested.\n", len(session.Resources), session.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var dial proxy.DialFunc
	if *statePath != "" {
		e, err := loginEngine(*statePath, *pin, *caFile)
		if err != nil {
			return err
		}
		e.Client.Profile, err = headerOptions.apply(e.Client.Profile)
		if err != nil {
			return err
		}
		defer e.Client.HTTP.CloseIdleConnections()
		router, err := routing.New(*mode, e.FetchPolicy, e.DialContext)
		if err != nil {
			return err
		}
		if _, err := router.Policy(ctx); err != nil {
			return fmt.Errorf("initial resource policy: %w", err)
		}
		dial = router.DialContext
	} else {
		if *mode != "vpn-only" || *pin != "" || *caFile != "" {
			return errors.New("mode and gateway trust flags require --state; session files contain their own trust settings")
		}
		session, err := native.LoadSession(*sessionPath)
		if err != nil {
			return err
		}
		session.HeaderProfile, err = headerOptions.apply(session.HeaderProfile)
		if err != nil {
			return err
		}
		dialer, err := native.NewDialer(session)
		if err != nil {
			return err
		}
		dial = dialer.DialContext
	}
	if command == "connect" {
		if flags.NArg() != 2 {
			return errors.New("usage: svpn-cli connect (--state FILE | --session FILE) HOST PORT")
		}
		conn, err := dial(ctx, "tcp", net.JoinHostPort(flags.Arg(0), flags.Arg(1)))
		if err != nil {
			var gatewayErr *native.GatewayError
			if *diagnostic != "" && errors.As(err, &gatewayErr) {
				if saveErr := writePrivateJSON(*diagnostic, gatewayErr); saveErr != nil {
					return saveErr
				}
			}
			return err
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		go func() {
			io.Copy(conn, os.Stdin)
			if cw, ok := conn.(interface{ CloseWrite() error }); ok {
				cw.CloseWrite()
			}
		}()
		_, err = io.Copy(os.Stdout, conn)
		return err
	}
	if flags.NArg() != 0 || *limit < 1 || *limit > 4096 {
		return errors.New("serve takes no positional arguments; max-connections must be 1..4096")
	}
	if *httpAddr == "" && *socksAddr == "" {
		return errors.New("enable at least one listener")
	}
	server := proxy.New(dial, *limit)
	type endpoint struct {
		name     string
		listener net.Listener
		serve    func(context.Context, net.Listener) error
	}
	var endpoints []endpoint
	defer func() {
		for _, e := range endpoints {
			e.listener.Close()
		}
	}()
	for _, e := range []struct {
		name, address string
		serve         func(context.Context, net.Listener) error
	}{{"HTTP", *httpAddr, server.ServeHTTP}, {"SOCKS5", *socksAddr, server.ServeSOCKS}} {
		if e.address == "" {
			continue
		}
		listener, err := proxy.ListenLocal(e.address)
		if err != nil {
			return err
		}
		endpoints = append(endpoints, endpoint{e.name, listener, e.serve})
	}
	results := make(chan error, len(endpoints))
	for _, e := range endpoints {
		fmt.Fprintf(os.Stderr, "%s listening on %s (routing: %s; independent experimental TCP transport)\n", e.name, e.listener.Addr(), *mode)
		go func() { results <- e.serve(ctx, e.listener) }()
	}
	first := <-results
	cancel()
	for i := 1; i < len(endpoints); i++ {
		if err := <-results; first == nil {
			first = err
		}
	}
	return first
}

func loginEngine(path, pin, caFile string) (*engine.Engine, error) {
	s, err := readAuth(path)
	if err != nil {
		return nil, err
	}
	c, err := deviceClient(&s)
	if err != nil {
		return nil, err
	}
	var identity engine.Identity
	if json.Unmarshal(s.Exchange["data"], &identity) != nil {
		return nil, errors.New("exchanged login identity required; run auth finish and auth exchange")
	}
	e, err := engine.New(c, identity)
	if err != nil {
		return nil, err
	}
	e.CertificateSHA256 = pin
	e.CAFile = caFile
	return e, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "svpn-cli:", err)
		os.Exit(1)
	}
}
