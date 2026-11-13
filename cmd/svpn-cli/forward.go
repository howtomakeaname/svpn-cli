package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/howtomakeaname/svpn-cli/internal/forward"
	"github.com/howtomakeaname/svpn-cli/internal/native"
	"github.com/howtomakeaname/svpn-cli/internal/proxy"
)

func loopbackEndpoint(address string, allowZero bool) bool {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	p, portErr := strconv.Atoi(port)
	minimum := 1
	if allowZero {
		minimum = 0
	}
	return err == nil && ip != nil && ip.IsLoopback() && portErr == nil && p >= minimum && p <= 65535
}

func (a *application) runForward(args []string) error {
	f := a.newFlagSet("forward")
	var options connectionOptions
	options.bind(f)
	listen := f.String("listen", "127.0.0.1:0", "local loopback TCP listener; port 0 auto-selects")
	target := f.String("target", "", "authorized destination HOST:PORT (required)")
	limit := f.Int("max-connections", 128, "maximum concurrent forwarded streams, 1..4096")
	if err := a.parseFlags(f, args); err != nil {
		return err
	}
	if err := options.validate(); err != nil {
		return err
	}
	address, err := native.CanonicalAddress(*target)
	if err != nil || f.NArg() != 0 || !loopbackEndpoint(*listen, true) || *limit < 1 || *limit > 4096 {
		return usageError("forward requires --target HOST:PORT, a loopback --listen address, and --max-connections 1..4096; no positional arguments")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dial, cleanup, err := options.open(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	listener, err := proxy.ListenLocal(*listen)
	if err != nil {
		return &cliError{Code: "LISTENER_FAILED", Message: "Cannot bind local forwarding listener.", exit: 4, cause: err}
	}
	return a.forwardStreams(ctx, "forward", listener, dial, address, *limit, map[string]any{
		"direction": "local_to_remote", "listen": listener.Addr().String(), "target": address,
		"mode": options.mode, "target_connectivity_tested": false,
	})
}

func (a *application) forwardStreams(ctx context.Context, command string, listener net.Listener, dial proxy.DialFunc, target string, limit int, details map[string]any) error {
	defer listener.Close()
	if a.json {
		if err := a.event(command, "ready", details); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(a.errOut, "%s listening on %s -> %s\n", command, listener.Addr(), target)
	}
	if err := forward.Serve(ctx, listener, dial, target, limit); err != nil {
		return remoteFailure(err)
	}
	if a.json {
		return a.event(command, "stopped", map[string]any{"reason": "shutdown"})
	}
	return nil
}
