Experimental svpn-cli release with an automation interface for agents.

- Versioned `--json` results, redacted errors and categorized exit codes.
- Text and JSON command discovery, including flags, examples and execution effects.
- Read-only `auth inspect` with local login stages and next actions.
- Explicit non-interactive callback import via private file or stdin; browser login/MFA remains user-driven.
- NDJSON proxy readiness/shutdown events with actual dynamically assigned listener ports.
- Raw `connect` stdout remains compatible with SSH ProxyCommand, including in JSON mode.

Core access features:

- Browser SSO/MFA handoff, private device state and per-resource access tickets.
- Loopback HTTP CONNECT, ordinary HTTP and SOCKS5 TCP proxies.
- `vpn-only` for upstream routing and `auto` for policy-based VPN/direct routing.
- Configurable compatibility headers, explicit TLS trust and fail-closed routing.
- Linux/macOS/Windows builds for amd64 and arm64; each archive includes license notices and examples.

All three operating systems run native unit, race and vet checks in CI. Live VPN/SSH integration has been verified on Linux; macOS and Windows deployment compatibility still needs real-session validation.

This release supports TCP only. Active tunnels currently expire with their resource ticket. Automatic TGT renewal, UDP, TUN and deployment-specific additional challenges are not supported. Binaries are not platform code-signed or notarized.

Verify the downloaded archive with `SHA256SUMS.txt`. Never share your authentication state or callback URL.
