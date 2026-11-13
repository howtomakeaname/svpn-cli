package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/howtomakeaname/svpn-cli/internal/privatefs"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func privateTestInput(t *testing.T, data []byte) string {
	t.Helper()
	f, err := privatefs.CreateTemp(t.TempDir(), "input-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestSSHCredentialFilesAndStrictKnownHosts(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(key)
	hosts := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"ssh.internal.example:22"}, signer.PublicKey()) + "\n"
	if err := os.WriteFile(hosts, []byte(line), 0644); err != nil {
		t.Fatal(err)
	}
	password := privateTestInput(t, []byte("secret-password\n"))
	config, err := sshConfig("test-user", hosts, "", "", password)
	if err != nil || len(config.Auth) != 1 {
		t.Fatal("private password file rejected", err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	if err := config.HostKeyCallback("ssh.internal.example:22", remote, signer.PublicKey()); err != nil {
		t.Fatal("trusted host key rejected", err)
	}
	if err := config.HostKeyCallback("unknown.example:22", remote, signer.PublicKey()); err == nil || classifyError(err).Code != "SSH_HOST_KEY_REJECTED" {
		t.Fatal("unknown host key accepted")
	}
	block, err := ssh.MarshalPrivateKey(key, "test")
	if err != nil {
		t.Fatal(err)
	}
	identity := privateTestInput(t, pem.EncodeToMemory(block))
	if _, err := sshConfig("test-user", hosts, identity, "", ""); err != nil {
		t.Fatal("private key rejected", err)
	}
	block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "test", []byte("secret-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	encrypted := privateTestInput(t, pem.EncodeToMemory(block))
	if _, err := sshConfig("test-user", hosts, encrypted, "", ""); err == nil || classifyError(err).Code != "SSH_KEY_PASSPHRASE_REQUIRED" {
		t.Fatal("encrypted key silently accepted without a passphrase")
	}
	passphrase := privateTestInput(t, []byte("secret-passphrase\n"))
	if _, err := sshConfig("test-user", hosts, encrypted, passphrase, ""); err != nil {
		t.Fatal("encrypted key with private passphrase rejected", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(password, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := sshConfig("test-user", hosts, "", "", password); err == nil || classifyError(err).Code != "INVALID_SSH_INPUT" {
			t.Fatal("publicly readable password file accepted")
		}
	}
}

func TestSSHSecretFilesAreBoundedAndNeverPrompt(t *testing.T) {
	for _, content := range [][]byte{nil, []byte("one\ntwo"), make([]byte, 4097)} {
		path := privateTestInput(t, content)
		if _, err := sshSecret(path); err == nil || classifyError(err).Code != "INVALID_SSH_INPUT" {
			t.Fatal("empty, multiline or oversized secret accepted")
		}
	}
}
