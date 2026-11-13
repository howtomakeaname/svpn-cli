Experimental svpn-cli release adding UDP, Linux TUN and explicit TLCP gateway transport.

- SOCKS5 UDP ASSOCIATE with preserved datagram boundaries, client endpoint binding, bounded flows and cleanup when the control TCP connection closes.
- Independent TCP/UDP policy matching and ticket caches. Protected protocol/port denials never fall back to direct routing.
- Linux TUN IPv4/IPv6 TCP/UDP ingress, including inherited descriptors for isolated application namespaces. This first mode requires vpn-only; routes, addresses and DNS are configured externally.
- Opt-in gateway TLCP 1.1 with SM2/SM3 and SM4 GCM/CBC. Explicit CA trust verifies both signing and encryption certificates. Single-leaf pins and fallback to ordinary TLS are refused.
- Read-only capabilities discovery for agents, distinguishing platform features from unprobed deployment compatibility.

The existing browser SSO/MFA handoff, structured JSON/NDJSON interface, policy-based proxy modes, raw SSH ProxyCommand, local TCP forwarding and verified SSH reverse forwarding remain available.

Validation includes three native operating-system test/race/vet jobs, six OS/architecture packages, and an independent GmSSL 3.2.0 interoperability CI job. Linux live validation recorded 300 successful transfer batches, 450 successful repeated DNS queries, TCP/UDP policy refusal and temporary-resource cleanup. Local GmSSL validation separately verified five 8 MiB echo batches per cipher suite; it does not establish compatibility with a production national-crypto gateway.

The bundled docs/performance-v0.3.md includes arithmetic means, sample standard deviations, medians, effective counts and sanitized per-batch data. It describes one variable network path, not a throughput guarantee.

Limitations:

- UDP is framed over TLS/TCP; raw UDP/QUIC/WireGuard transports are not implemented.
- TUN device access is Linux-only. Domain-aware TUN auto mode, DNS interception, fake-IP and ICMP are not implemented.
- SPA packet authorization and RFC 8998 national-crypto TLS 1.3 are not implemented. TLCP client-certificate authentication is not provided; control-plane SSO/API still uses ordinary HTTPS.
- Real VPN sessions on macOS/Windows and real TLCP gateway deployments still need validation.
- Resource tickets still bound active tunnel lifetime. Automatic TGT renewal, deployment-specific additional challenges and automatic reconnection are not implemented.

Linux/macOS/Windows archives are supplied for amd64 and arm64, with dependency notices and examples. Binaries are not platform code-signed or notarized. Verify downloads using SHA256SUMS.txt and keep authentication state private.
