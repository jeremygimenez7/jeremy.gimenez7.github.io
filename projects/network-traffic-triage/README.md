# Network Traffic Triage Tool

A beginner-friendly, static browser application that turns a Wireshark packet-list CSV into an explainable network activity report. It uses rules, not AI or machine learning.

**Detection tells an analyst where to look. Investigation determines what actually happened.**

## Open on Windows — no installation

1. Open `C:\Users\Jeremy\OneDrive\Documents\Network-Tool` in File Explorer.
2. Double-click `index.html` (or right-click → Open with → Microsoft Edge).
3. Select a demo button or choose a Wireshark `.csv` file.
4. Review warnings, the overview, analysis coverage, and alert explanations.
5. Change thresholds and select **Apply thresholds** to recalculate. **Reset Defaults** restores the educational settings.

Keep the project files together. No terminal, package manager, backend, account, API key, or internet connection is required. The app can also be served unchanged by a static website host. A host will receive ordinary requests for application files, but this application does not send the selected CSV to it. Do not enable host-injected analytics or tracking.

## Educational Use

Only capture and analyse traffic from systems and networks you own or are authorised to monitor. Use the fictional samples for public demonstrations rather than exposing real users, hostnames, addresses, or other sensitive capture contents.

An anomaly is a starting point for investigation, not proof of compromise. Observe unusual behaviour, identify the source and destination, establish the protocol and expected device role, look for supporting indicators, correlate other telemetry, then decide whether further investigation is warranted. No alerts does not mean a capture is safe.

## Exporting from Wireshark

Open Wireshark, capture authorised traffic, and stop the capture. Use the CSV packet-dissections / packet-list export under File → Export Packet Dissections, retaining column headings. Menu wording may vary. Check whether the export includes all packets or only displayed/selected packets. Upload the exported CSV, not a PCAP or PCAPNG. Numeric network addresses are preferable to resolved names for the destination-spread rule.

## Supported CSV fields

UTF-8, comma-separated text; optional UTF-8 BOM; Windows or Unix line endings; quoted commas, escaped double quotes, and multiline quoted fields. Semicolon-delimited and UTF-16 exports are not supported. Blank records are skipped. Inconsistent field counts, ambiguous duplicate recognised columns, malformed quotes, binary nulls, empty datasets, and unknown-only headers produce an error rather than a partial report.

Column matching ignores case, punctuation, spaces, and underscores:

| Field | Recognised examples |
|---|---|
| Source | Source, Source IP, src, ip.src, ipv6.src, srcip, Source Address |
| Destination | Destination, Destination IP, dst, ip.dst, ipv6.dst, dstip, Destination Address |
| Protocol | Protocol, proto, _ws.col.Protocol |
| Length | Length, len, frame.len, Packet Length, size |
| Info | Info, Information, Summary, _ws.col.Info |
| Time | Time, Timestamp, frame.time_relative |
| Packet number | No., Number, frame.number |

Missing source, destination, protocol, length, or Info columns generate warnings and disable affected calculations. Invalid/blank lengths are excluded from the average, not counted as zero. Unknown extra columns are ignored. Source and destination values are treated as exported labels, not verified device identities.

Limits: 10 MiB (10 × 1024 × 1024 bytes) and 50,000 packet rows. Processing runs on the main browser thread and can briefly pause the interface on larger inputs. Export a smaller subset if necessary. Packet previews and displayed alert cards are limited to 200 matches; full-capture counts and detections are not truncated.

## Rules and default thresholds

Every rule triggers on **more than**, not equal to, the threshold. Counts cover the entire imported export, not a time window.

| Rule | Default | Priority | Evidence |
|---|---:|---|---|
| High Packet Volume | 50 | Low | Packet count for a source |
| Possible Network Scanning | 10 | Medium | Distinct numeric destination IPs for a source |
| Possible Port Scanning | 10 | Medium | Distinct inferred destination ports per source/destination pair |
| High ICMP Activity | 30 | Medium | ICMP and ICMPv6 packets per source |
| High DNS Activity | 30 | Low | DNS-labelled packets per source |
| Repeated Source-to-Destination Communication | 40 | Low | Directional pair count and its most common protocol |

All thresholds are configurable, nonnegative whole numbers. Priority represents where to investigate, not certainty or business impact. Version 1 rules assign Low or Medium; the filter supports all four priority labels for consistency. No arbitrary attack probability or investigation score is provided.

Port extraction accepts only TCP/UDP-labelled rows with an Info field beginning with numeric `source-port → destination-port` (also `->` or `>`), with ports in 0–65535. It does not assume every number in Info is a port. Coverage is shown in the report. Replies to many client ephemeral ports can look like scanning: verify which side initiated the connections. DNS counts include replies and do not prove high query volume, domain abuse, or beaconing. TCP SYN/flag analysis is deferred.

**Thresholds are educational defaults, not universal security thresholds.** A busy server may legitimately generate thousands of packets, while the same activity from another endpoint might deserve investigation. Capture duration, host role, normal workload, and expected applications all matter. Backups, updates, authorised vulnerability scans, monitoring, and troubleshooting can trigger these rules.

## Dashboard and filters

The overview shows total packets, unique source/destination labels, busiest endpoints, most common exported protocol, average valid length, ranked top-ten hosts, and protocol counts. Protocol labels are retained rather than guessing application identity; a TLS version may appear separately from TCP or HTTPS. Unavailable protocol values are clearly labelled.

Source and destination filters use case-insensitive substring matching. Protocol uses an exact exported label. Severity affects alerts only. Search covers packet fields and alert explanations. An alert matches address/protocol filters when one of its supporting packets matches all those filters. Aggregate alert evidence and the overview always remain full-capture values; filtering never silently changes thresholds or recounts detections.

## Privacy and security design

- File selection reads data into browser memory using local file APIs.
- No fetch, XMLHttpRequest, WebSocket, telemetry, external assets, AI providers, cookies, browser storage, or backend.
- Demo text is bundled in `sample-data.js`, so sample buttons need no network requests, including when opened with `file://`.
- A restrictive Content Security Policy blocks network connections and unapproved content. It is defence in depth, not a replacement for safe DOM handling.
- Uploaded values are inserted as text with `textContent`; never as HTML, scripts, expressions, or URLs to visit. CSV formula-looking strings are also plain text; there is no spreadsheet export.
- Extension checking is combined with UTF-8 decoding, size limits, and structural parsing; a `.csv` extension alone is not trusted as proof of valid contents.
- Errors clear the previous report so stale results cannot be confused with a failed upload. Clear data drops application references and visible results; it does not promise forensic memory erasure or delete your source file.

**Your project folder is inside OneDrive.** The app does not upload captures, but OneDrive or another sync service may upload files saved in its folders independently. Keep real captures in a non-synced location. Browser extensions, operating-system services, and modified hosting environments are outside the application's control.

## Samples and recruiter demonstration

All sample addresses are private or documentation ranges. Samples are fictional, not recorded malware activity.

| Button / file | Packets | Expected default result |
|---|---:|---|
| Load Normal Sample / `samples/normal-traffic.csv` | 18 | No alerts |
| Load Suspicious Sample / `samples/high-volume-traffic.csv` | 60 | One High Packet Volume alert for 10.0.0.25 |
| Load Mixed SOC Lab / `samples/mixed-soc-lab.csv` | 176 | Seven alerts covering all six rules |

Demo sequence:
1. Load normal traffic: explain that no threshold alerts does not prove safety.
2. Load the high-volume sample: show 60 packets against the >50 threshold. Explain that backups or updates could produce the same count.
3. Load the mixed lab: show 10.0.0.40 contacting 15 IPs and 10.0.0.30 sending 36 ICMP packets to 12 IPs. Review authorised scanning and monitoring as benign explanations.
4. Show the port, DNS, and repeated-pair alerts and their suggested investigations.
5. Raise the packet threshold to 60: show why configuration changes the result, not the underlying evidence.
6. Finish with: “Detection tells an analyst where to look. Investigation determines what actually happened.”

## Tests

Open `C:\Users\Jeremy\OneDrive\Documents\Network-Tool\tests\tests.html` in your browser. It runs dependency-free parser, rule, threshold-boundary, sample, and safe-alert-rendering tests locally and reports pass/fail. No special browser flags are required for this test page.

Manual interface checks: load each demo; upload each sample CSV; drag and drop a sample; apply/reset thresholds; try address/protocol/severity/search filters; choose a non-CSV file; upload malformed text named `.csv`; navigate using Tab and Enter; check narrow-screen layout. Test with real authorised exports to assess column compatibility. Automated tests do not replace screen-reader, visual, or real-capture testing.

## Files and architecture

- `index.html`: semantic page, privacy messages, controls, educational guidance.
- `styles.css`: dark responsive theme and visible focus states.
- `script.js`: CSV parser, rule engine, safe rendering, and local upload handling. `window.Triage` exposes pure analysis helpers for the test page.
- `sample-data.js`: embedded copies of the three CSV samples; keep these in sync if changing samples.
- `samples/`: downloadable/openable fictional CSVs.
- `tests/`: browser tests with no dependencies.

## Limitations and false positives

CSV lacks much of the original PCAP information. Encrypted traffic limits payload visibility. Packet volume alone does not establish malicious behaviour. NAT, resolved names, IPv6 textual variants, and shared systems can complicate attribution or distinct-host counts. Equivalent IPv6 spellings are not fully canonicalised. Protocol labels depend on Wireshark's interpretation; packets labelled as higher-layer protocols are not also counted as TCP/UDP for port extraction. ICMPv6 neighbour discovery can legitimately be busy. No direction-of-session inference, query classification, time-window analysis, baseline learning, retransmission deduplication, or capture-integrity verification is performed. Repeated communication does not establish periodicity or beaconing. Every exported row is counted as one packet record.

The tool does not perform malware analysis and does not replace Wireshark, IDS, SIEM, or professional network monitoring. A report describes only the supplied export, not the health or security of the whole network.

## Future improvements — not implemented in Version 1

Direct PCAP and PCAPNG support; TCP flag analysis; time-window detections; traffic baselining; network graphs; GeoIP; threat-intelligence enrichment; DNS-domain analysis; exportable SOC reports; IDS-style detection rules. Any future enrichment must explicitly revisit privacy and data-source design; Version 1 includes no external APIs.