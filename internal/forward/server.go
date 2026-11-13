// Package forward relays fixed TCP endpoints without adding an application protocol.
package forward

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/howtomakeaname/svpn-cli/internal/proxy"
)

// Serve owns listener and all accepted connections. Cancellation closes active
// streams too; a failed dial closes only that incoming stream, with no fallback.
func Serve(ctx context.Context, listener net.Listener, dial proxy.DialFunc, target string, limit int) error {
	if listener == nil || dial == nil || limit < 1 || limit > 4096 {
		return errors.New("listener, dial function and connection limit 1..4096 required")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	var active sync.WaitGroup
	defer func() { cancel(); listener.Close(); active.Wait() }()
	sem := make(chan struct{}, limit)
	for {
		incoming, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			incoming.Close()
			continue
		}
		active.Add(1)
		go func() {
			defer active.Done()
			defer func() { <-sem }()
			defer incoming.Close()
			stopIncoming := context.AfterFunc(ctx, func() { incoming.Close() })
			defer stopIncoming()
			upstream, err := dial(ctx, "tcp", target)
			if err != nil {
				return
			}
			defer upstream.Close()
			stopUpstream := context.AfterFunc(ctx, func() { upstream.Close() })
			defer stopUpstream()
			proxy.Relay(incoming, incoming, upstream)
		}()
	}
}
