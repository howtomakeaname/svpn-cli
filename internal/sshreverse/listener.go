// Package sshreverse opens remote TCP listeners over an existing authenticated
// SSH transport. The transport itself may be supplied by a VPN dialer.
package sshreverse

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/howtomakeaname/svpn-cli/internal/proxy"
	"golang.org/x/crypto/ssh"
)

var ErrRemoteListen = errors.New("remote SSH listener refused")

type Listener struct {
	net.Listener
	client *ssh.Client
	stop   func() bool
	cancel context.CancelFunc
	once   sync.Once
}

func (l *Listener) Close() error {
	var err error
	l.once.Do(func() {
		l.stop()
		l.cancel()
		// Closing the dedicated SSH connection releases the remote port and
		// channels even if a cancel-tcpip-forward reply would otherwise hang.
		err = l.client.Close()
		l.Listener.Close()
	})
	return err
}

func Listen(ctx context.Context, dial proxy.DialFunc, address, bind string, config *ssh.ClientConfig) (*Listener, error) {
	if dial == nil || config == nil || config.HostKeyCallback == nil || config.User == "" || len(config.Auth) == 0 {
		return nil, errors.New("SSH user, authentication and host key verification are required")
	}
	setup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := dial(setup, "tcp", address)
	if err != nil {
		return nil, err
	}
	// Do not change the underlying connection's deadline: the VPN transport may
	// enforce an earlier ticket expiry. Context cancellation bounds setup instead.
	stopSetup := context.AfterFunc(setup, func() { conn.Close() })
	defer stopSetup()
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	sshConn, channels, requests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		return nil, fmt.Errorf("SSH handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, channels, requests)
	listener, err := client.Listen("tcp", bind)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("%w: %v", ErrRemoteListen, err)
	}
	if !stopSetup() && setup.Err() != nil {
		client.Close()
		return nil, setup.Err()
	}
	if err := setup.Err(); err != nil {
		client.Close()
		return nil, err
	}
	life, cancelLife := context.WithCancel(ctx)
	l := &Listener{Listener: listener, client: client, cancel: cancelLife, stop: context.AfterFunc(life, func() { client.Close() })}
	ok = true
	go keepalive(life, client)
	return l, nil
}

func keepalive(ctx context.Context, client *ssh.Client) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Any reply, including "unsupported request", demonstrates liveness.
			// A silent peer must not retain a dead listener until ticket expiry.
			timeout := time.AfterFunc(10*time.Second, func() { client.Close() })
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			timeout.Stop()
			if err != nil {
				return
			}
		}
	}
}
