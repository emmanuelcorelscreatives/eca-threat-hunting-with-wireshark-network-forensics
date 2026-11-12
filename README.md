# Threat Hunting with Wireshark: Network Forensics

Emmanuel Corels Academy · EMMANUEL CORELS

Course overview and lesson order for the saved Wireshark threat-hunting and network-forensics curriculum.

[Full curriculum: 24 stages and 145 lessons](curriculum.json)

## Course stages

- Stage 1 (7 lessons)
- Stage 2 — Build a Reliable and Isolated Analysis Lab (6 lessons)
- Stage 3 — Evidence Quality, Capture Limits and Preservation (6 lessons)
- Stage 4 — Turn a Suspicion into a Testable Hunt (6 lessons)
- Stage 5 — Build Precise Filters and Useful Analyst Views (6 lessons)
- Stage 6 — Read TCP, UDP and Reassembled Conversations (6 lessons)
- Stage 7 — Baseline Hosts, Services and Traffic Patterns (6 lessons)
- Stage 8 — Scale Packet Triage with TShark and Capture Utilities (6 lessons)
- Stage 9 — Investigate DNS Behaviour and Suspicious Resolution (6 lessons)
- Stage 10 — Reconstruct Web Delivery and Initial Access Clues (6 lessons)
- Stage 11 — Recognize Scanning, Discovery and Network Anomalies (6 lessons)
- Stage 12 — Investigate Authentication and Credential-Related Signals (6 lessons)
- Stage 13 — Find and Validate Beacon-Like Behaviour (6 lessons)
- Stage 14 — Investigate TLS, QUIC and Visibility Limits (6 lessons)
- Stage 15 — Investigate DNS Tunneling and Alternative Channels (6 lessons)
- Stage 16 — Correlate a Multi-Protocol Command-and-Control Case (6 lessons)
- Stage 17 — Investigate SMB and Windows East-West Activity (6 lessons)
- Stage 18 — Investigate Remote Services Across Platforms (6 lessons)
- Stage 19 — Detect and Quantify Potential Data Exfiltration (6 lessons)
- Stage 20 — Reconstruct a Multi-Stage Network Intrusion (6 lessons)
- Stage 21 — Use Packet Evidence in Incident Response (6 lessons)
- Stage 22 — Build a Defensible Network Forensics Report (6 lessons)
- Stage 23 — Turn Hunts into Reusable Detections (6 lessons)
- Stage 24 — Capstone: Lead a Complete Threat Hunt (6 lessons)

## Using the course materials

Use each lesson’s matching capture and analysis instructions together. Filenames, filters, packet identifiers and expected values are lesson-specific.

## Available practice labs

- [Follow a complete DNS transaction: synthetic offline exercise](practice/dns-baseline/README.md) — Stage 9, Lesson 1. Other case packs are being prepared; this is a supplemental fixture, not recorded production evidence.

## Reviewed concept worksheets

[Browse the reviewed worksheets and reasoning keys](materials/concept-worksheets-v1/index.md), in matching lesson order. These are supplemental exercises; capture-dependent lab packs are still being prepared.

## Verified packet foundations

[Five source-aligned exercises with three deterministic synthetic PCAPs](practice/packet-foundations/README.md), worksheets, keys, provenance and executed decoding proofs. These supplement the lectures and do not replace their unavailable case evidence.

## Reviewed concept worksheets

[Browse the reviewed worksheets and reasoning keys](materials/concept-worksheets-v2/index.md), in matching lesson order. These are supplemental exercises; capture-dependent lab packs are still being prepared.

## Verified supplemental containment practice

[A source-aligned containment exercise with a deterministic synthetic PCAP](practice/containment-decision/supplemental-scenario.md), worksheets, keys, provenance and executed decoding proofs. These supplement the lectures and do not replace their unavailable case evidence.

## Reviewed concept worksheets

[Browse the reviewed worksheets and reasoning keys](materials/concept-worksheets-v3/index.md), in matching lesson order. These are supplemental exercises; capture-dependent lab packs are still being prepared.

## Verified blank timeline workbook

[A source-aligned blank timeline workbook with checked schema and native Calc validation](practice/unified-evidence-timeline/README.md), worksheets, keys, provenance and executed decoding proofs. These supplement the lectures and do not replace their unavailable case evidence.

## Capstone intake materials

[Capstone intake exercise](practice/capstone-intake/setup.md): labelled synthetic case brief, inventory, collection register, rules of engagement, worksheet and answer guide. This lesson does not supply or claim the later investigation results.

## Reviewed concept worksheets

[Browse the reviewed worksheets and reasoning keys](materials/concept-worksheets-v4/index.md), in matching lesson order. These are supplemental exercises; capture-dependent lab packs are still being prepared.

## GUI and TShark selection lab

[Translate a GUI filter into TShark](practice/translate-gui-filter-tshark/README.md): complete synthetic PCAP, reproducible offline builder, worksheet and execution-backed key; native Wireshark screenshots and TShark logs document the same frame selection.

## Fields, strings and repeated values lab

[Work with Fields, Strings and Repeated Values](practice/fields-strings-repeated-values/README.md): Complete synthetic PCAP, safe reproducible builder, checked decoded CSV, worksheet and measured key; Linux and Windows command results and native GUI evidence verify all saved filter exercises.

## Boolean filter scope lab

[Build a Filter That Answers the Question](practice/boolean-filter-logic/README.md): Complete synthetic PCAP, safe reproducible builder, checked decoded CSV, worksheet and measured key; Linux and Windows command results and native GUI evidence verify all saved filter exercises.

## Remote access and authentication correlation lab

[Correlate Remote Access with Identity Events](practice/ssh-auth-correlation/README.md): Actual controlled SSH packet capture with explicit offline training aliases, matching sanitized authentication records, exact offline reconstruction, worksheet, bounded answer guide, and native Linux command and GUI evidence.

## Bounded ATT&CK mapping practice

[Map Behaviour to ATT&CK Carefully](materials/stage-4/lesson-3/README.md): Separate synthetic DNS, TCP and HTTP practice capture with planned scenario context, safe reproducible offline builder, worksheet, bounded answer guide and independently reviewed native Linux evidence. Protocol mapping is not an incident finding.

## Unexpected outbound connection practice

[Project 1: The Unexpected Outbound Connection](materials/stage-4/lesson-5/project-1-supplemental/README.md): Separately labelled synthetic DNS and HTTP exchanges, authored asset and schedule context, safe reproducible offline builder, worksheet, bounded answer guide and independently reviewed native Linux evidence. The unavailable historical case remains separate.

## Scanner authorization practice

[Compare Authorized Scanners and Adversarial Discovery](practice/scanner-authorization/README.md): Separately labelled synthetic TCP discovery patterns with matching approval, job and ticket records, a safe offline builder, worksheet, bounded answer guide and independently reviewed native Linux evidence. The out-of-scope C:445 contact remains unresolved; no live scan is required.

## Complete DNS transaction practice

[Follow a Complete DNS Transaction](materials/stage-9/lesson-1/README.md): Two distinct worked samples: a reproducible synthetic client/upstream model and a separately documented actual Academy-owned loopback DNS collection. Includes safe hash-checked setup, worksheets, checked transaction keys and native Linux evidence. The learner-owned-capture assignment and historical case remain separate.

## Inter-arrival timing practice

[Measure Inter-Arrival Timing](materials/stage-13/lesson-2/README.md): Separate synthetic TCP and HTTP exercise with a safe reproducible offline builder, independent raw-packet checker, scoped connection-start and request-start timing, source-bound native Wireshark views, worksheet, answer guide and authorized own-capture homework. The worked fixture is not an incident finding or completed learner collection.

## Beacon-candidate documentation practice

[Document a Beacon Candidate](materials/stage-13/lesson-6/README.md): Separate synthetic TCP exercise with two explicitly bounded candidate comparisons, a safe offline builder, independent raw-packet checker, exact scoped native Wireshark views and ten-second graphs, retraceable ranking brief, worksheet and qualified answer guide. Packet timing and scenario roles do not establish a process, collection coverage, approval or a historical incident.

## Jitter, gaps and persistent-session timing practice

[Interpret Jitter, Gaps and Long-Lived Sessions](materials/stage-13/lesson-3/README.md): Separate synthetic TCP/HTTP exercise with regular, variable and apparent-gap attempt series, retry exclusion, a persistent connection with one visible HTTP request, safe offline rebuild, independent raw-packet checks, native graph-bin and accepted-start delta observations, worksheet, answer guide and a separate authorized-file assignment. Timing alone does not establish process identity, purpose, collector health or a historical incident.

## Positive and negative display-filter lab

[Test a Filter Against Positive and Negative Examples](practice/filter-positive-negative/README.md): Seven-frame explicitly synthetic mixed TCP, UDP and ARP practice with reproducible offline builder, exact executed filter checks, worksheet, checked answer guide and native Linux GUI evidence.

## Establish the environment and asset roles practice

[Establish the Environment and Asset Roles](materials/stage-7/lesson-1/README.md): Separate synthetic role-mapping exercise with bundled PCAP and PCAPNG, inventory validity dates and mapping sources, checked endpoint/packet results, supported/provisional/conflicting/unknown classifications, safe offline builder, comparison worksheet, answer guide and separate authorized-file assignment. Packet addresses do not establish real asset roles or ownership.

## Install and verify analysis tools

[Install and Verify the Analysis Tools](materials/stage-2/lesson-2/README.md): Complete capability-record exercise with actual Linux ordinary-user tool checks, native File Open and About evidence, optional synthetic DNS capture and safe offline builder. Offline readiness, interface discovery and conditional live permission remain separate. No Windows or live capture execution claimed.

## Failures, retries and suspicious bursts

[Distinguish Failures, Retries and Suspicious Bursts](materials/stage-12/lesson-02/README.md): Complete supplemental synthetic CSV correlation exercise with Kerberos, LDAP and NTLM scenario rows, identity and change records, uncertainty-aware worksheet and answer guide, offline Python validator, exact controls and actual execution/rejection evidence. This is an authored scenario, not native host logs or decoded packet evidence.

## Split, merge and inspect lab

[Split, Merge and Inspect Captures](practice/split-merge-inspect-captures/README.md): executable synthetic two-source workflow, safe replay, original and derivative manifests, split/window/merge outputs, packet provenance key, actual logs and native GUI evidence.

## Endpoints and conversations practice

[Pivot Through Endpoints and Conversations](materials/stage-7/lesson-3/README.md): Separate synthetic IPv4 and IPv6 exercises with reproducible offline builders, executed endpoint and conversation totals, scope/fan-out comparisons, retransmission and truncation packet checks, native Linux observations, worksheet and worked answer guide. Roles and unique application data remain uncertain; this is not historical incident evidence.

## Minimum practical lab

[Choose the Minimum Practical Lab](practice/minimum-practical-lab/README.md): minimum workstation planning, optional synthetic DNS PCAP/PCAPNG, safe offline builder, worksheet and independently checked key. No GUI execution is claimed.

## Ticket and relay investigation limits

[Understand Ticket and Relay Investigation Limits](materials/stage-12/lesson-4/README.md): Complete synthetic offline identity, destination and host record-analysis lab, keyed timeline, provisional handoff, reproducible CSV checker, and optional separate authorized-capture assignment. No supplied packet capture, relay finding, credential theft or historical incident is claimed.

## Redirects and download chains lab

[Investigate redirects and download chains](materials/stage-10/lesson-2/README.md): complete synthetic PCAP, reproducible offline builder, worksheet and execution-backed key; actual TShark logs verify observed cross-connection HTTP follow-ups, unresolved proposals, cache and partial responses, with an updater comparison.

## HTTP headers and forms lab

[Inspect Headers, Forms and Content Types](practice/http-header-form-practice/README.md): Explicitly synthetic HTTP headers, URL-encoded and multipart form practice, finite-capture limits, exact offline reconstruction, worksheet, checked key and native Linux evidence.

## DNS timing and direction lab

[Use Timing and Direction to Strengthen the Case](practice/dns-timing-direction/README.md): Separate synthetic offline DNS capture, safe deterministic builder, checked packet key, directional worksheets, and bounded fictional host-event comparison.

## Verified transport evidence exercise

[A source-aligned synthetic multi-interface PCAPNG exercise](materials/stage-6/lesson-2/README.md), worksheets, keys, generators and executed decoding proofs. These supplement the lectures and do not replace their unavailable case evidence.

## HTTPS visibility comparison lab

[Explain What HTTPS Hides](materials/stage-10/lesson-6/README.md): Actual owned loopback captures of two scripted TLS 1.3 sessions, candidate and known benign updater, with measured packet facts, SNI and conversation exercises, read-only validation, optional safe local collection, a mock endpoint linkage task, worksheet and bounded answers. Encrypted traffic does not identify a saved object or execution.

## ARP, DHCP and local discovery lab

[Examine ARP, DHCP and Local Discovery](practice/arp-dhcp-local-discovery/README.md): Two independently decoded synthetic Ethernet traces with ARP, DHCP initial lease and renewal, relay DHCP, genuine mDNS and an intentional malformed-payload counterexample; offline generator/verifier and worked exercises.

## Cleartext exposure training lab

[Inspect Cleartext Exposure in Training Traffic](practice/cleartext-training-practice/README.md): New synthetic FTP/HTTP training capture, exact offline builder, redacted worksheet and answer guide, real native Linux command verification and independently checked restricted GUI execution.

## I/O Graph interval comparison

[Build Time-Based Views with I/O Graphs](materials/stage-7/lesson-4/README.md): Independently reviewed new offline synthetic practice comparing1sec/10sec AllPackets/tcp graphs, actual native graph navigation, packets and scope, checked worksheet/key and deterministic safe builder. No historical finding or network-wide silence claim.

## Fragmentation and offload artifacts lab

[Recognize Fragmentation and Offload Artifacts](materials/stage-6/lesson-6/README.md): Deterministic offline IPv4 and IPv6 fragment cases, shortened saved frames, TCP-gap baseline, explicitly simulated offload comparison, and source-bound native Linux validation.

## Controlled TLS session practice

[Decrypt a Controlled TLS Session](materials/stage-14/lesson-3/README.md): Separate Academy TLS1.2 encrypted teaching exchange with matching disposable public key log, same-session before/after executed evidence, native Linux packet-list observations, worksheet, verified answer guide and secret-handling exercises. This is synthetic practice, not a historical case or learner-owned capture. Real case secrets and decrypted derivatives require restricted storage.

## Failed and partial connection practice

[Analyze Failed and Partial Connections](materials/stage-11/lesson-2/README.md): Separate synthetic14frame TCP/ICMP practice with SYN retries, reset direction, partial and completed handshakes, two correctly quoted IPv4 unreachable errors, safe offline generator, independent raw checker, executed CLI pivots, native Linux filter views, worksheet, verified answer guide and a separate authorized-recording assignment. Packets alone establish neither intent nor authorization.

## Preserve originals and work on copies

[Preserve Originals and Work on Copies](practice/preserve-originals/README.md): Separately labelled zero-packet pcapng handling fixture, full SHA-256 handoff, fail-closed operating-system copy script, actual Linux PowerShell 7 execution and negative controls, worksheet and checked answer guide. Preserves the unavailable narrated Windows case limitation; no Windows 5.1 or GUI execution is asserted.

## Evidence-bounded response scoping practice

[Scope the Response Without Overreaching](materials/stage-18/lesson-6/README.md): Separate synthetic two-observation-point TCP exercise with complete PCAP/PCAPNGs, offline builder, 14 supporting scenario records, actual checksum and decoded-field checks, worksheet and measured key. Practice bounded source and identity correlation, competing administrator context, coverage gaps and targeted collection. Ports and timing do not establish application behavior, actor identity, authorization or compromise.

## DNS answer to subsequent connections lab

[A full DNS pivot practice kit](materials/stage-9/lesson-4/README.md), with three synthetic captures, CNAME and multiple A/AAAA answers, IPv6 sessions, upstream and DNS-absent viewpoints, safe builder, verifier, worksheet, checked solutions and executed Linux proof. These supplement the lectures and do not replace their unavailable case evidence.

## Project 6 Internal Hop supplemental lab

[Project 6: The Internal Hop](practice/project-6-internal-hop-supplement/setup.md): Two synthetic observation-point captures, supporting scenario records, executable offline rebuild, full worksheet and bounded answer guide with actual CLI validation.
