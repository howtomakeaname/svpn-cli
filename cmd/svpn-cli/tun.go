package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/howtomakeaname/svpn-cli/internal/tun"
)

func (a *application) runTUN(args []string) error {
	f := a.newFlagSet("tun")
	var options connectionOptions
	options.bind(f)
	device := f.String("device", "", "Linux TUN name; requires permission to attach/create it")
	fd := f.Int("fd", -1, "inherited Linux TUN descriptor (>=3), as an alternative to --device")
	mtu := f.Int("mtu", 1500, "packet MTU, 1280..65535; configure the interface to match")
	limit := f.Int("max-connections", 128, "maximum combined TCP and UDP flows, 1..4096")
	if err := a.parseFlags(f, args); err != nil {
		return err
	}
	if err := options.validate(); err != nil {
		return err
	}
	if f.NArg() != 0 || (*device == "") == (*fd < 0) || *fd == 0 || *fd == 1 || *fd == 2 || *mtu < 1280 || *mtu > 65535 || *limit < 1 || *limit > 4096 {
		return usageError("tun requires exactly one of --device NAME or --fd NUMBER, valid MTU/limit, and no positional arguments")
	}
	// Without a DNS-to-flow association, auto mode cannot safely recognize a
	// domain-only resource from an IP packet. Keep this first TUN mode strict.
	if options.mode != "vpn-only" {
		return usageError("tun currently requires --mode vpn-only; domain-aware auto routing needs DNS integration")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dial, cleanup, err := options.open(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	file, name, err := tun.Open(*device, *fd)
	if err != nil {
		return &cliError{Code: "TUN_DEVICE_FAILED", Message: "Cannot open a Linux TUN device; supply a permitted device or inherited descriptor.", exit: 4, cause: err}
	}
	var readyErr error
	err = tun.Run(ctx, file, *mtu, *limit, dial, func() {
		if a.json {
			readyErr = a.event("tun", "ready", map[string]any{"device": name, "mtu": *mtu, "mode": options.mode, "protocols": []string{"tcp", "udp"}, "route_configuration": "external", "dns_hijack": false})
			if readyErr != nil {
				cancel()
			}
		} else {
			fmt.Fprintf(a.errOut, "TUN %s ready; configure IP routes and DNS externally.\n", name)
		}
	})
	if readyErr != nil {
		return readyErr
	}
	if err != nil {
		return remoteFailure(err)
	}
	if a.json {
		return a.event("tun", "stopped", map[string]any{"reason": "shutdown"})
	}
	return nil
}
