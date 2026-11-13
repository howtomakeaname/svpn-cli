package main

import (
	"encoding/json"
	"runtime"
	"slices"
	"testing"
)

func TestCapabilitiesDoNotClaimUnimplementedOrUnprobedFeatures(t *testing.T) {
	code, out, errOut := invoke("--json", "capabilities")
	if code != 0 || errOut != "" {
		t.Fatal(code, errOut)
	}
	var result struct {
		Data struct {
			DeploymentProbed bool `json:"deployment_probed"`
			Features         map[string]struct {
				Available bool     `json:"available"`
				Ingress   []string `json:"ingress"`
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Data.DeploymentProbed || result.Data.Features["spa"].Available || result.Data.Features["tls13_sm"].Available {
		t.Fatal("unsupported compatibility advertised")
	}
	if slices.Contains(result.Data.Features["udp"].Ingress, "linux_tun") != (runtime.GOOS == "linux") {
		t.Fatal("UDP ingress advertised an unavailable TUN platform")
	}
	if !result.Data.Features["udp"].Available || result.Data.Features["tun"].Available != (runtime.GOOS == "linux") {
		t.Fatal("incorrect platform capability")
	}
}
