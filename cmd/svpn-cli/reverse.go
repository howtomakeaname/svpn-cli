package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/howtomakeaname/svpn-cli/internal/native"
	"github.com/howtomakeaname/svpn-cli/internal/privatefs"
	"github.com/howtomakeaname/svpn-cli/internal/sshreverse"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func (a *application) runReverse(args []string) error {
	f := a.newFlagSet("reverse")
	var options connectionOptions
	options.bind(f)
	sshHost := f.String("ssh-host", "", "authorized SSH server HOST:PORT reached using VPN routing (required)")
	user := f.String("ssh-user", "", "SSH account on that server (required)")
	knownHosts := f.String("known-hosts", "", "trusted OpenSSH known_hosts file (required; never auto-accept host keys)")
	identity := f.String("identity-file", "", "private SSH key file; mutually exclusive with --password-file")
	passphrase := f.String("key-passphrase-file", "", "private passphrase file for an encrypted --identity-file")
	password := f.String("password-file", "", "private SSH password file; mutually exclusive with --identity-file")
	listen := f.String("listen", "127.0.0.1:0", "remote loopback listener on the SSH server; port 0 auto-selects")
	target := f.String("target", "", "local service on a literal loopback IP:PORT (required)")
	limit := f.Int("max-connections", 128, "maximum concurrent forwarded streams, 1..4096")
	if err := a.parseFlags(f, args); err != nil {
		return err
	}
	if err := options.validate(); err != nil {
		return err
	}
	address, err := native.CanonicalAddress(*sshHost)
	if err != nil || f.NArg() != 0 || !loopbackEndpoint(*listen, true) || !loopbackEndpoint(*target, false) || *limit < 1 || *limit > 4096 {
		return usageError("reverse requires --ssh-host HOST:PORT, loopback --listen and --target addresses, --max-connections 1..4096, and no positional arguments")
	}
	if *user == "" || len(*user) > 256 || strings.ContainsAny(*user, "\r\n\x00") || *knownHosts == "" || (*identity == "") == (*password == "") || (*passphrase != "" && *identity == "") {
		return usageError("reverse requires --ssh-user, --known-hosts and exactly one of --identity-file or --password-file; --key-passphrase-file requires --identity-file")
	}
	config, err := sshConfig(*user, *knownHosts, *identity, *passphrase, *password)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dial, cleanup, err := options.open(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	listener, err := sshreverse.Listen(ctx, dial, address, *listen, config)
	if err != nil {
		var problem *cliError
		var gateway *native.GatewayError
		if errors.As(err, &problem) || errors.As(err, &gateway) {
			return err
		}
		if errors.Is(err, sshreverse.ErrRemoteListen) {
			return &cliError{Code: "REMOTE_LISTENER_FAILED", Message: "SSH server refused remote forwarding; check forwarding permissions and port availability.", exit: 5, cause: err}
		}
		return &cliError{Code: "SSH_CONNECTION_FAILED", Message: "Cannot establish the SSH connection; check VPN policy, SSH credentials and server configuration.", exit: 5, cause: err}
	}
	// DialContext is bounded separately for each local stream and cannot recurse
	// into VPN routing. The target is restricted to a literal loopback address.
	local := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return a.forwardStreams(ctx, "reverse", listener, local.DialContext, *target, *limit, map[string]any{
		"direction": "remote_to_local", "ssh_host": address, "listen": listener.Addr().String(),
		"target": *target, "mode": options.mode, "target_connectivity_tested": false,
	})
}

func privateSSHInput(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || privatefs.Check(f) != nil || info.Size() > limit {
		return nil, &cliError{Code: "INVALID_SSH_INPUT", Message: "SSH credential input must be a bounded private regular file.", exit: 4}
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit || len(data) == 0 {
		return nil, &cliError{Code: "INVALID_SSH_INPUT", Message: "Cannot read a nonempty bounded SSH credential file.", exit: 4}
	}
	return data, nil
}

func sshSecret(path string) ([]byte, error) {
	data, err := privateSSHInput(path, 4096)
	if err != nil {
		return nil, err
	}
	secret := strings.TrimSuffix(string(data), "\n")
	secret = strings.TrimSuffix(secret, "\r")
	if secret == "" || strings.ContainsAny(secret, "\r\n\x00") {
		return nil, &cliError{Code: "INVALID_SSH_INPUT", Message: "SSH secret file must contain one nonempty line.", exit: 4}
	}
	return []byte(secret), nil
}

func sshConfig(user, hosts, identity, passphrase, password string) (*ssh.ClientConfig, error) {
	verify, err := knownhosts.New(hosts)
	if err != nil {
		return nil, &cliError{Code: "INVALID_KNOWN_HOSTS", Message: "Cannot load the trusted OpenSSH known_hosts file.", exit: 4, cause: err}
	}
	config := &ssh.ClientConfig{User: user, HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := verify(hostname, remote, key); err != nil {
			return &cliError{Code: "SSH_HOST_KEY_REJECTED", Message: "SSH host key is unknown, changed or revoked; obtain a verified known_hosts entry.", exit: 5, cause: err}
		}
		return nil
	}}
	if password != "" {
		secret, err := sshSecret(password)
		if err != nil {
			return nil, err
		}
		config.Auth = []ssh.AuthMethod{ssh.Password(string(secret))}
		return config, nil
	}
	key, err := privateSSHInput(identity, 1<<20)
	if err != nil {
		return nil, err
	}
	var signer ssh.Signer
	if passphrase != "" {
		secret, err := sshSecret(passphrase)
		if err != nil {
			return nil, err
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, secret)
	} else {
		signer, err = ssh.ParsePrivateKey(key)
	}
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, &cliError{Code: "SSH_KEY_PASSPHRASE_REQUIRED", Message: "Encrypted SSH key requires --key-passphrase-file.", exit: 3}
		}
		return nil, &cliError{Code: "INVALID_SSH_INPUT", Message: "Cannot parse the private SSH key with the supplied passphrase.", exit: 4}
	}
	config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	return config, nil
}
