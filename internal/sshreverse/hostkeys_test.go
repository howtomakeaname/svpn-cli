package sshreverse

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestRecordedKeyAlgorithmOnMultiKeyServer(t *testing.T) {
	for _, changed := range []bool{false, true} {
		address, key, _ := newSSHServer(t, false)
		if changed {
			_, private, _ := ed25519.GenerateKey(rand.Reader)
			signer, _ := ssh.NewSignerFromKey(private)
			key = signer.PublicKey()
		}
		path := filepath.Join(t.TempDir(), "known_hosts")
		hashed := knownhosts.HashHostname(knownhosts.Normalize(address))
		if err := os.WriteFile(path, []byte(knownhosts.Line([]string{hashed}, key)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		verify, err := knownhosts.New(path)
		if err != nil {
			t.Fatal(err)
		}
		algorithms := HostKeyAlgorithms(verify, address)
		if len(algorithms) == 0 || algorithms[0] != ssh.KeyAlgoED25519 || slices.Contains(algorithms, ssh.KeyAlgoRSA) {
			t.Fatal("did not prefer recorded secure key type", algorithms)
		}
		config := configFor(key)
		config.HostKeyCallback, config.HostKeyAlgorithms = verify, algorithms
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		listener, err := Listen(ctx, (&net.Dialer{}).DialContext, address, "127.0.0.1:0", config)
		if changed {
			var rejected *knownhosts.KeyError
			if !errors.As(err, &rejected) {
				t.Fatal("changed key was accepted or lost its verification failure", err)
			}
		} else {
			if err != nil {
				t.Fatal("recorded Ed25519 key failed on a multi-key server", err)
			}
			listener.Close()
		}
		cancel()
	}
}
