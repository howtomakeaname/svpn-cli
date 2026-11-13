# Architecture figure prompt

Generated with the built-in imagegen tool. `architecture.png` is the selected output, reviewed against the CLI routing and transport behavior. Panel (a) shows logical control interactions; panel (b) shows request routing, with responses implicit over established connections.

Use case: scientific-educational
Asset type: a camera-ready computer networking paper architecture figure, embedded in a GitHub README.
Primary request: completely redraw the svpn-cli architecture as a rigorous, minimalist scholarly figure with two panels. This must look like an actual systems paper figure, NOT a marketing infographic, presentation slide, or UI flowchart.

VISUAL SPECIFICATION:
White canvas and white interiors of every box. Absolutely no colored fills, gradients, textures, shadows, gloss, giant headings, cards, heavy rounded corners, clip art or icons. Thin uniform strokes, squared rectangles, regular-weight Helvetica/Arial-style type, precise alignment, generous white gutters. Only the small panel letters (a) and (b) may be bold. All other text, including headings and node labels, uses normal weight. Small component titles rather than decorative titles. Use black/charcoal for all text and ordinary arrows, muted dark teal only for the VPN data path. Do not add a large legend. Wide landscape composition, approximately 2400 x 1500, readable at 960 px display width. Use large enough body text for real documentation, not tiny annotations.

STRUCTURE:
Two separate horizontal panels stacked vertically, with NO connecting lines between the panels. Each panel is a distinct view. A small label at the upper left of each panel:
"(a) Control plane"
"(b) Data plane"
Panel (a) occupies about 25% of figure height; panel (b) about 60%; two concise notes below. Neither panel gets a filled background or a large outside frame.

PANEL (a): Three aligned boxes, left to right, with generous spacing.
Left box: "Browser" and beneath it "SSO / MFA".
Middle box: "CLI session" and beneath it "Device-bound state".
Right box: "Access API" and beneath it "Policy + resource tickets".
Between Browser and CLI session draw a thin horizontal DOUBLE-HEADED arrow labelled "Login URL / callback".
Between CLI session and Access API draw a thin horizontal DOUBLE-HEADED arrow labelled "HTTPS".
These are logical interactions, not a sequence diagram. Do not draw Browser -> Access API or any connection to panel (b).

PANEL (b): Single data path with three explicit routing outcomes.
A thin gray dashed rectangular boundary labelled "svpn-cli" contains the ingress, policy router and VPN connector ONLY. The remote gateway and remote targets are OUTSIDE this boundary on the right. The label is small and modest at the top edge, not an oversized title.
Inside the left of this boundary, ONE tall box with heading "Local ingress", then three separate regular-weight lines:
"HTTP / CONNECT (TCP)"
"SOCKS5 (TCP / UDP)"
"Linux TUN* (TCP / UDP)"
One thin rightward arrow from this ingress box to ONE central box "Policy router", with small second line "Host / port / protocol".
Three separate outgoing branches from Policy router, no crossing connectors:
1. Upper branch labelled "Allowed resource" leads to an inside-boundary box "VPN connector", with second line "Resource ticket". A rightward muted teal arrow from VPN connector crosses the boundary to an external box "VPN gateway", then another rightward muted teal arrow to a separate external box "Authorized service". Above the connector-to-gateway link place "TLS + CONNECT". Both gateway and service are clearly outside CLI. Gateway is NOT the service.
2. Middle/lower branch labelled "Unmatched in auto" goes straight to a separate external box "Other destination". This is the direct path, bypassing gateway completely. Label the outgoing line "Direct". There is NO separate Direct dial box: keep the architecture lean.
3. A short downward branch ends in the word "Reject", inside the CLI boundary. Beside this branch place two short lines "Denied / error" and "Unmatched in vpn-only". Reject has NO outgoing arrows.
Do not draw any link from VPN connector to the direct path. Protected failures NEVER fall back to direct. The paths are directional request-routing arrows; responses are implicit over the established connections.

FOOTNOTES, exact regular-weight text, left-aligned and legible:
"* Linux TUN supports vpn-only; routes and DNS are configured externally."
"UDP is framed over TLS/TCP. TLCP 1.1 is an optional gateway mode."

NO additional labels or content. No vendor, organization, university or real endpoint names. No SPA, QUIC, WireGuard or unsupported protocol claims. Do not draw each CLI command as its own box; a figure explains component boundaries, not the command reference. Avoid duplicate full pipelines for routing modes. Layout quality, scientific restraint and semantic correctness matter most.
