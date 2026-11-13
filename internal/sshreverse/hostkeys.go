package sshreverse

import (
	"crypto/ed25519"
	"errors"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyAlgorithms prefers the host's recorded key types. Without this, a
// multi-key server can negotiate ECDSA even when known_hosts pins Ed25519.
// The callback still verifies the real key during the handshake; this function
// only selects algorithms, never adds a key or relaxes verification.
func HostKeyAlgorithms(verify ssh.HostKeyCallback, address string) []string {
	supported := ssh.SupportedAlgorithms().HostKeys
	if verify == nil {
		return supported
	}
	// A local placeholder public key asks the verifier for matching records via
	// KeyError.Want. It is never sent to a peer, and needs no private key. Let the
	// known_hosts parser handle hashed hosts, ports, wildcards and revoked keys.
	placeholder, _ := ssh.NewPublicKey(make(ed25519.PublicKey, ed25519.PublicKeySize))
	err := verify(address, &net.TCPAddr{IP: net.IPv4zero, Port: 22}, placeholder)
	var mismatch *knownhosts.KeyError
	if !errors.As(err, &mismatch) || len(mismatch.Want) == 0 {
		return supported
	}
	wanted := make(map[string]bool)
	for _, known := range mismatch.Want {
		wanted[known.Key.Type()] = true
	}
	var preferred, certificates []string
	for _, algorithm := range supported {
		if strings.Contains(algorithm, "-cert-") {
			// Keep certificate negotiation available for @cert-authority entries,
			// after any exact host keys. The real callback validates the CA.
			certificates = append(certificates, algorithm)
			continue
		}
		keyType := algorithm
		if algorithm == ssh.KeyAlgoRSASHA256 || algorithm == ssh.KeyAlgoRSASHA512 {
			keyType = ssh.KeyAlgoRSA
		}
		if wanted[keyType] {
			preferred = append(preferred, algorithm)
		}
	}
	return append(preferred, certificates...)
}
