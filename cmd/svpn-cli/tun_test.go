package main

import "testing"

func TestTUNRejectsUnsafeOrInvalidSetupBeforeReadingCredentials(t *testing.T) {
	for _, options := range [][]string{
		{"--fd", "0"},
		{"--device", "svpn0", "--fd", "3"},
		{"--device", "svpn0", "--mode", "auto"},
		{"--device", "svpn0", "--gateway-tls", "tlcp"},
		{"--device", "svpn0", "--gateway-tls", "unknown"},
		{"--device", "svpn0", "--mtu", "100"},
	} {
		args := append([]string{"--json", "tun", "--state", "missing-private-state"}, options...)
		code, out, errOut := invoke(args...)
		if code != 2 || out != "" || decodeResponse(t, errOut).OK {
			t.Fatal(options, code, out, errOut)
		}
	}
}
