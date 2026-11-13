# Architecture figure prompts

Generated and edited with the built-in imagegen tool. `architecture.png` is the selected result. The client boundary spans the control and data planes; dashed arrows show policy and ticket dependencies. Browser interactions are logical login handoffs, and data-plane arrows show request routing, with responses implicit over established connections.

## Generation

Use case: scientific-educational
Asset type: a networking software architecture figure for the svpn-cli README.
Primary request: draw a refined, colorful but restrained academic systems figure, with a clear THREE-COLUMN by TWO-ROW architecture. The client boundary spans both rows, so the reader sees how authorization supports traffic forwarding. This is a new composition, not a recolor of a generic two-panel flowchart.

VISUAL STYLE:
White background; balanced flat pastel fills; thin colored outlines; dark slate typography. Clean regular-weight sans-serif with only small semibold component titles. Consistent text padding and generous gutters. No textures, gradients, shadows, 3D, pictograms, watermarks or oversized headings. Rounded corners are subtle, about 5 px. Looks like a carefully designed camera-ready research figure, not a slide deck. Landscape around 2400 x 1440. Body labels must remain legible at 960 px display width.
Palette: muted blue #4778AD with #EAF2FB for client modules, violet #7664A6 with #F0EBF8 for authorization, teal #278C82 with #E5F3EE for VPN path and protected resources, ochre #AA8746 with #FAF1DF for direct traffic, terracotta #B86561 with #FAE8E5 for rejection. Text #23344A. Use color meaningfully and consistently. Fill the CLI boundary with only a nearly-white cool tint, not a saturated large panel.

GRID AND BOUNDARIES:
Three modest column headings across the top, exact text:
"Users & applications" (left, approximately 15% width)
"svpn-cli" (center, approximately 55% width)
"Remote services" (right, approximately 30% width).
ONE thin blue-gray boundary encloses all CLI modules in the center column, spanning upper control row and lower data row. Browser and applications are OUTSIDE it on the left; Access API, VPN gateway, Authorized service and Direct destination are OUTSIDE it on the right. Do not put every column in a large colored panel.
Inside the central client region, two small left-aligned row labels: "Control plane" above the upper row, and "Data plane" above the lower row. A very fine horizontal divider may separate the rows, but it must NOT obstruct vertical dependency arrows.

UPPER CONTROL ROW:
Left, outside CLI: a small neutral pale box "Browser" / "SSO / MFA".
Center, inside CLI: one wider pale-violet box "Control client" / "Device session · policy · grants". It spans the horizontal positions of the router and VPN connector underneath.
Right, outside CLI: one pale-violet box "Access API".
Browser <-> Control client is a violet DOUBLE-HEADED horizontal arrow labelled "Login URL / callback".
Control client <-> Access API is a violet DOUBLE-HEADED horizontal arrow labelled "HTTPS".
From separate lower ports of Control client, draw two thin violet DASHED vertical arrows, with no crossing:
- straight down to Policy router below, labelled "Policy";
- straight down to VPN connector below, labelled "On-demand ticket".
These are logical control dependencies, NOT application data. The policy arrow must end ONLY at Policy router; the ticket arrow must end ONLY at VPN connector. Do not connect them to each other.

LOWER DATA ROW:
Outside CLI on the left: a pale neutral-blue box "Applications", with two smaller lines "curl · SSH · agents" and "mihomo / Clash".
A rightward blue arrow enters the CLI boundary and reaches a pale-blue box "Local ingress", containing exactly these three lines:
"HTTP / CONNECT"
"SOCKS5 TCP / UDP"
"Linux TUN*"
A rightward blue arrow then reaches the central pale-blue "Policy router" box. Its smaller subtitle is "Host · port · protocol". Make this box wide enough to fit the subtitle with real padding.
The router has THREE DISTINCT, NONCROSSING routing outcomes:
1. Straight right, a teal arrow labelled "Allowed" to an inside-CLI pale-blue "VPN connector" box. This receives the dashed on-demand-ticket arrow from above. Then a teal arrow crosses the CLI boundary, labelled "TLS + CONNECT", to an OUTSIDE pale-mint "VPN gateway" box. Another teal arrow reaches a separate OUTSIDE pale-mint "Authorized service" box further right. Gateway and service are separate, aligned, externally placed boxes. No node is omitted.
2. From the lower-right side of Policy router, an ochre branch drops to a separate lower horizontal lane, labelled "Unmatched in auto". It bypasses VPN connector and gateway and ends at an OUTSIDE pale-sand box "Direct destination", positioned below the gateway/service lane. Label the outgoing segment "Direct". This path never touches the gateway.
3. From a DIFFERENT lower port of Policy router, a short terracotta arrow goes down to a small pale-blush "Reject" box INSIDE CLI. Its adjacent label is two lines: "Denied / error" and "Unmatched in vpn-only". Place this rejection lane below and apart from the direct lane so labels do not collide. Reject has no outgoing arrow.
There is NO fallback arrow from VPN connector or gateway to Direct destination. No crossing data paths. Responses are implicit over established connections.

BOTTOM NOTES, modest but legible:
"Dashed: authorization dependencies. Solid: request routing."
"* Linux TUN: TCP/UDP, vpn-only; routes and DNS configured externally."
"UDP is framed over TLS/TCP. TLCP 1.1 is an optional gateway mode."

COMPOSITION QUALITY:
Every component has clear padding. Match columns and align upper Control client over the exact two lower modules receiving its policy and ticket arrows. All remote nodes stay visibly beyond the CLI right boundary. Keep all routing labels away from box borders and arrowheads. No giant badges, no boxed legend, no extra text, no branding or real organization endpoints. Avoid duplicate complete pipelines. The reader should immediately recognize user inputs, the client boundary, authorization dependencies and the three possible traffic outcomes.

## Legend correction

Use case: precise-object-edit
Input image: edit target, an existing svpn-cli architecture figure.
Change ONLY the FIRST footnote line at the bottom:
Replace "Dashed: authorization dependencies. Solid: request routing."
with exactly "Dashed arrows denote policy and ticket dependencies."
The solid arrows in the upper control row are logical control interactions, so the original blanket "Solid: request routing" description was ambiguous. This is only a footer text correction.
Preserve every other word, node, box, arrow, arrowhead, color, line path, font size, panel boundary, alignment, remaining footnotes and canvas dimensions exactly. Keep the replacement left-aligned at the original first footnote position, in the same font and size. Do not redraw, omit, move or recolor any other element. No extra text.
