package main

import (
	"fmt"
	"runtime"
)

// Capabilities describe this executable, never the authorization or negotiated
// features of an unqueried deployment. Agents can distinguish the two without
// probing gateways or interpreting a connection failure as a direct route.
func (a *application) runCapabilities(args []string) error {
	f := a.newFlagSet("capabilities")
	if err := a.parseFlags(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return usageError("capabilities takes no positional arguments")
	}
	features := map[string]any{
		"tcp":          map[string]any{"available": true, "ingress": []string{"http", "socks5", "forward", "reverse", "connect"}},
		"udp":          map[string]any{"available": true, "ingress": []string{"socks5_udp_associate", "linux_tun"}, "vpn_transport": "datagrams_over_tls_tcp", "socks_fragments": false, "raw_udp_vpn": false},
		"tun":          map[string]any{"available": runtime.GOOS == "linux", "platforms": []string{"linux"}, "routing_modes": []string{"vpn-only"}, "route_configuration": "external", "requires": "permitted TUN device or inherited descriptor", "dns_hijack": false, "icmp": false},
		"gateway_tls":  map[string]any{"available": true, "default": true, "minimum_version": "1.2"},
		"gateway_tlcp": map[string]any{"available": true, "version": "1.1", "opt_in": true, "trust": "explicit_ca_for_both_server_certificates", "client_certificates": false},
		"tls13_sm":     map[string]any{"available": false, "reason": "RFC 8998 TLS 1.3 cipher suites are not implemented"},
		"spa":          map[string]any{"available": false, "reason": "SPA packet authorization is not implemented"},
	}
	return a.result("capabilities", fmt.Sprintf("TCP and SOCKS5 UDP: available. Linux TUN available on this platform: %v. Gateway TLCP 1.1: explicit opt-in with CA trust. SPA and RFC 8998 TLS 1.3: unavailable. Deployment compatibility has not been probed; use --json for details.", runtime.GOOS == "linux"), map[string]any{"platform": runtime.GOOS, "deployment_probed": false, "runtime_prerequisites_checked": false, "features": features})
}
