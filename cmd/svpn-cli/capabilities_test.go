package main

import (
	"encoding/json"
	"runtime"
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
				Available bool `json:"available"`
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Data.DeploymentProbed || result.Data.Features["spa"].Available || result.Data.Features["tls13_sm"].Available {
		t.Fatal("unsupported compatibility advertised")
	}
	if !result.Data.Features["udp"].Available || result.Data.Features["tun"].Available != (runtime.GOOS == "linux") {
		t.Fatal("incorrect platform capability")
	}
}
