# Architecture figure prompts

Generated with the built-in imagegen tool. The second prompt corrects the dependency labels in the first result; `architecture.png` contains the corrected result.

## Initial generation

Use case: infographic-diagram
Asset type: replacement architecture figure for a software project's GitHub README.
Primary request: Draw a precise, exceptionally clean academic systems architecture figure for "svpn-cli". Redesign from scratch, with one shared traffic path rather than two duplicated diagrams. Make it immediately readable at a README display width of 960 px. Wide landscape canvas, approximately 2400 x 1500, white background.
Style: publication-quality computer networking paper figure. Flat vector-like raster rendering, restrained pale blue and teal fills, charcoal text, thin consistent orthogonal connectors, generous whitespace, clear alignment. Use clean sans-serif typography with large legible text. No 3D, gradients, shadows, decorative illustrations, pictograms, logos, watermarks, or fake UI.

Overall layout: a narrow authorization strip across the top; beneath it one large "svpn-cli" boundary containing the local ingress, policy router, and VPN connector, while the VPN gateway and destination servers stay OUTSIDE the CLI boundary on the right. Three routing outcomes are arranged on separate horizontal levels without crossing lines. A concise legend and two factual footnotes sit at the bottom. Each label must be spelled exactly and appear only where requested.

TOP STRIP, titled "Session and authorization":
Left-to-right: "Browser SSO / MFA" -> "Device session", then a fork to two stacked small boxes "Resource policy" and "Resource tickets".
A blue dashed dependency connector from Resource policy goes to the Policy router below. A blue dashed connector from Resource tickets goes to the VPN connector below. Keep these dashed connectors separate and do not make a Device session -> Policy router shortcut. The strip represents logical authorization dependencies, not user traffic.

MAIN FIGURE:
Inside the svpn-cli boundary, on the left, heading "Local ingress", vertically stacked three small cards:
1 "HTTP proxy" with sublabel "TCP"
2 "SOCKS5" with sublabel "TCP / UDP"
3 "Linux TUN" with sublabel "TCP / UDP · vpn-only"
These three cards merge into ONE central box "Policy router" with small sublabel "Host · port · protocol".
Do not draw a path between ingress cards. All three feed the router.
The upper outcome from Policy router is a solid teal arrow labelled "Allowed resource" to the "VPN connector" box inside the CLI boundary. Then continue horizontally across the boundary to an OUTSIDE box "VPN gateway", then to an OUTSIDE box "Authorized service". Each consecutive pair has a clear directional arrow pointing right. Label only the connector-to-gateway arrow "TLS + CONNECT".
The middle outcome from Policy router is a solid gray arrow labelled "Unmatched · auto only" to a box "Direct dial" inside the CLI boundary, then horizontally across the boundary to an OUTSIDE box "Other destination". This path must bypass the VPN gateway completely.
The bottom outcome from Policy router is a short amber arrow to a small box "Reject" inside the CLI boundary. Along this arrow place the text "Denied / error" and on a second line "Unmatched in vpn-only". Reject has NO outgoing connector. The unmatched-in-vpn-only outcome also applies to the TUN ingress, which is vpn-only.
Keep all three outcomes distinct and never connect the VPN connector to Direct dial. Do not draw retry or fallback arrows. Avoid overlapping edge labels or oversized empty containers.

BOTTOM LEGEND:
A short teal arrow sample labelled "VPN path"; a gray arrow sample labelled "Direct path"; a blue dashed arrow sample labelled "Authorization dependency"; an amber arrow sample labelled "Reject".
Two footnotes in legible small text, exact wording:
"UDP uses framed datagrams over TLS/TCP. TLCP 1.1 is an optional gateway mode."
"TUN routes and DNS are configured externally. Protected traffic never falls back to direct."

Technical and textual constraints: HTTP proxy is TCP only. SOCKS5 and Linux TUN can carry TCP and UDP. TUN is only a local ingress into the SAME policy/connector engine, not a VPN outer transport. The real VPN gateway must be visible separately from the authorized service. The VPN connector is client code. TLS + CONNECT is between client connector and gateway. The authorized service is reached through the gateway. No SPA, no QUIC, no WireGuard, no RFC 8998 claim, no platform promises, no organization, school or vendor names or real IP addresses. No extra text beyond specified headings/labels/footnotes. Prioritize semantic accuracy, uncluttered hierarchy, and readable labels.

## Dependency label correction

Use case: precise-object-edit
Asset type: README systems architecture figure.
Input image: edit target, all content and layout already present.
Change ONLY the two small resource-box text labels in the top "Session and authorization" strip:
- The UPPER box, currently labelled "Resource policy", must instead read exactly "Resource tickets".
- The LOWER box, currently labelled "Resource tickets", must instead read exactly "Resource policy".
This text swap fixes the existing dashed dependencies: the upper box's right-hand dashed path ends at VPN connector, and the lower box's left-hand dashed path ends at Policy router.
Preserve ALL connector paths, arrowheads, box positions, all other text, typography, sizes, colors, margins, and canvas dimensions exactly. Do not redraw or move any arrows. Do not change any other label. Both new labels use the exact same font/size/weight as the old labels. No extra text.
