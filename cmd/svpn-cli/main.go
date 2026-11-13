package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

	"github.com/howtomakeaname/svpn-cli/internal/engine"
	"github.com/howtomakeaname/svpn-cli/internal/native"
	"github.com/howtomakeaname/svpn-cli/internal/proxy"
)

func (a *application) run(args []string) error {
	if len(args) == 0 {
		return a.showHelp(a.newFlagSet(""))
	}
	if args[0] == "version" {
		f := a.newFlagSet("version")
		if err := a.parseFlags(f, args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return usageError("version takes no positional arguments")
		}
		return a.result("version", versionString(), map[string]any{"version": version, "commit": commit, "build_date": buildDate, "os": runtime.GOOS, "arch": runtime.GOARCH})
	}
	if args[0] == "help" {
		f := a.newFlagSet("")
		if err := a.parseFlags(f, args[1:]); err != nil {
			return err
		}
		if f.NArg() == 0 {
			return a.showHelp(f)
		}
		// Help traverses the same parsers as execution, so it cannot drift from
		// implemented flags and never performs network or filesystem mutations.
		return a.run(append(append([]string{}, f.Args()...), "--help"))
	}
	if len(args) > 0 && args[0] == "policy" {
		return a.runPolicy(args[1:])
	}
	if len(args) > 0 && args[0] == "ticket" {
		return a.runTicket(args[1:])
	}
	if len(args) > 0 && args[0] == "auth" {
		return a.runAuth(args[1:])
	}
	if args[0] == "forward" {
		return a.runForward(args[1:])
	}
	command := args[0]
	if command != "check" && command != "connect" && command != "serve" {
		return usageError("Unknown command; use svpn-cli --help.")
	}
	flags := a.newFlagSet(command)
	options := connectionOptions{mode: "vpn-only"}
	var diagnostic string
	httpAddr, socksAddr, limit := "127.0.0.1:17890", "127.0.0.1:17891", 128
	if command == "check" {
		flags.StringVar(&options.session, "session", "", "private JSON file with already-issued resource tickets")
	} else {
		options.bind(flags)
	}
	if command == "connect" {
		flags.StringVar(&diagnostic, "diagnostic", "", "save gateway refusal response to a private JSON file")
	}
	if command == "serve" {
		flags.StringVar(&httpAddr, "http", httpAddr, "HTTP loopback listener; empty disables, port 0 auto-selects")
		flags.StringVar(&socksAddr, "socks", socksAddr, "SOCKS5 loopback listener; empty disables, port 0 auto-selects")
		flags.IntVar(&limit, "max-connections", limit, "maximum concurrent proxy requests, 1..4096")
	}
	if err := a.parseFlags(flags, args[1:]); err != nil {
		return err
	}
	if err := options.validate(); err != nil {
		return err
	}
	if command == "check" {
		if flags.NArg() != 0 || options.session == "" {
			return usageError("check requires --session and no positional arguments")
		}
		session, err := loadSession(options.session)
		if err != nil {
			return err
		}
		return a.result("check", fmt.Sprintf("Session format valid: %d resources; expires %s. Connectivity has not been tested.", len(session.Resources), session.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")), map[string]any{"resource_count": len(session.Resources), "expires_at": session.ExpiresAt, "connectivity_tested": false})
	}
	if command == "connect" {
		if flags.NArg() != 2 {
			return usageError("connect requires HOST PORT after its options")
		}
		if _, err := native.CanonicalAddress(net.JoinHostPort(flags.Arg(0), flags.Arg(1))); err != nil {
			return usageError("connect requires a valid HOST and a numeric PORT in 1..65535")
		}
	} else if flags.NArg() != 0 || limit < 1 || limit > 4096 || (httpAddr == "" && socksAddr == "") {
		return usageError("serve takes no positional arguments, requires a listener, and --max-connections must be 1..4096")
	}
	if command == "serve" {
		for _, address := range []string{httpAddr, socksAddr} {
			if address == "" {
				continue
			}
			host, port, err := net.SplitHostPort(address)
			ip := net.ParseIP(host)
			p, portErr := strconv.Atoi(port)
			if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || p < 0 || p > 65535 {
				return usageError("listeners require a literal loopback IP and numeric port in 0..65535")
			}
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dial, cleanup, err := options.open(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	if command == "connect" {
		conn, err := dial(ctx, "tcp", net.JoinHostPort(flags.Arg(0), flags.Arg(1)))
		if err != nil {
			var gatewayErr *native.GatewayError
			if diagnostic != "" && errors.As(err, &gatewayErr) {
				if saveErr := writePrivateJSON(diagnostic, gatewayErr); saveErr != nil {
					return saveErr
				}
			}
			if errors.As(err, &gatewayErr) {
				return err
			}
			return remoteFailure(err)
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
		_, err = io.Copy(a.out, conn)
		return err
	}
	return a.serve(ctx, dial, options.mode, httpAddr, socksAddr, limit)
}

func (a *application) serve(ctx context.Context, dial proxy.DialFunc, mode, httpAddr, socksAddr string, limit int) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	server := proxy.New(dial, limit)
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
	}{{"HTTP", httpAddr, server.ServeHTTP}, {"SOCKS5", socksAddr, server.ServeSOCKS}} {
		if e.address == "" {
			continue
		}
		listener, err := proxy.ListenLocal(e.address)
		if err != nil {
			return &cliError{Code: "LISTENER_FAILED", Message: "Cannot bind a local proxy listener; check its address and port availability.", exit: 4, cause: err}
		}
		endpoints = append(endpoints, endpoint{e.name, listener, e.serve})
	}
	listeners := make(map[string]string, len(endpoints))
	for _, e := range endpoints {
		listeners[e.name] = e.listener.Addr().String()
	}
	// Bind every requested listener before publishing readiness. The event means
	// ingress is bound (and initial policy was fetched), not that a target was dialed.
	if a.json {
		if err := a.event("serve", "ready", map[string]any{"listeners": listeners, "mode": mode, "target_connectivity_tested": false}); err != nil {
			return err
		}
	}
	results := make(chan error, len(endpoints))
	for _, e := range endpoints {
		if !a.json {
			fmt.Fprintf(a.errOut, "%s listening on %s (routing: %s; experimental TCP transport)\n", e.name, e.listener.Addr(), mode)
		}
		go func() { results <- e.serve(ctx, e.listener) }()
	}
	first := <-results
	cancel()
	for i := 1; i < len(endpoints); i++ {
		if err := <-results; first == nil {
			first = err
		}
	}
	if first == nil && a.json {
		return a.event("serve", "stopped", map[string]any{"reason": "shutdown"})
	}
	return first
}

func loadSession(path string) (*native.Session, error) {
	s, err := native.LoadSession(path)
	if err != nil && !os.IsNotExist(err) && !os.IsPermission(err) {
		return nil, &cliError{Code: "INVALID_SESSION", Message: "Cannot load a valid, unexpired private session file.", exit: 4, cause: err}
	}
	return s, err
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
		return nil, authRequired("exchanged login identity required; run auth finish and auth exchange")
	}
	e, err := engine.New(c, identity)
	if err != nil {
		return nil, authRequired("a valid device-bound exchanged login identity is required")
	}
	e.CertificateSHA256 = pin
	e.CAFile = caFile
	return e, nil
}

func main() {
	os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr))
}
