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

## Visible TLS handshake practice

[Read the Visible TLS Handshake](materials/stage-14/lesson-1/README.md): Complete separate actual Academy loopback TLS1.3 lab, immutable PCAPNG, decoded hello offers and selections, opaque encrypted records, stream/context exercise, native views, verified answers and offline hash/field checks. No session secrets or original incident claims.

## Transfer purpose comparison lab

[Distinguish Backup, Synchronization, and Exfiltration](practice/backup-purpose-comparison/README.md): Explicitly synthetic offline TCP practice with fictional business records, deterministic builder, actual CLI checks, worksheet, and bounded answer guide.

## Follow Stream context lab

[Follow Streams Without Losing Context](practice/follow-stream-context/README.md): complete separate synthetic TCP and UDP captures, reproducible safe offline builder, worksheet and execution-backed key; actual native screenshots and TShark logs document directional content, Hex, Close, Back and adjacent context.

## Custom columns hunt lab

[Add Columns That Answer the Hunt Question](practice/columns-hunt/README.md): Twenty-frame offline synthetic custom-column practice with positive TLS SNI and repeated DNS answer fields, deterministic builder and validator, checked guides and actual independently reviewed native GUI evidence.

## Name-resolution anomalies practice

[Investigate Name-Resolution Anomalies](materials/stage-11/lesson-4/README.md): Separate synthetic 17-frame LLMNR, NBNS broadcast/configured-server and DNS exercise with later payload-free TCP traffic, assumed asset map, safe offline rebuild, independent raw-packet checks, native filter views, worksheet, answer guide and a separate authorized-file assignment. Unexpected replies and later connections do not establish authentication or credential capture.

## DNS query shape, diversity and volume practice

[Analyze Query Shape, Diversity and Volume](materials/stage-15/lesson-2/README.md): Separate synthetic DNS comparison of query shape, distinct names, query volume, A/AAAA/TXT types, NXDOMAIN and answer outcomes. Includes full PCAP, deterministic offline builder, independent TShark row checks, worksheet and verified answer guide. Authored controls and measurements do not establish a tunnel, exfiltration, process identity or a historical incident.

## Safe single-object HTTP export practice

[Export Visible Objects for Safe Examination](materials/stage-10/lesson-4/README.md): Complete separate synthetic HTTP exercise with a split inert response and an ordinary-page alternative. Includes actual single-row GUI export, packet and reassembly tracing, full Windows PowerShell hash evidence, safe offline builder, worksheet, artifact register and worked controls. Packet reconstruction and matching hashes do not establish endpoint saving or execution.

## Collection and outbound transfer clues

[Trace Collection and Outbound Transfer Clues](materials/stage-20/lesson-3/README.md): Independently reviewed two-view synthetic packet lab with fictional clock and NAT records, actual native Conversations and Follow Stream, exact deterministic reconstruction, worksheet and checked key. Data identity remains unresolved.

## Server names and certificates lab

[Use Server Names and Certificates Carefully](practice/server-names-certificates/README.md): Actual controlled loopback TLS1.2 and TLS1.3 handshakes, same-stream SNI/SAN analysis, exact offline reconstruction, executable fixture, worksheet, bounded answer key and independently reviewed native packet-list evidence.

## Endpoint and conversation batch summaries

[Summarize Endpoints and Conversations in Batches](materials/stage-8/lesson-3/README.md): Three separate synthetic offline capture sources with deterministic builder, original and working-copy hashes, per-file IPv4/TCP/UDP summaries, explicit statistics filters and their -Y distinction, native GUI comparisons, representative packets, worksheet, checked answer guide and an authorized-file extension. Repeated relationships do not establish independent events, maliciousness, users or processes.

## Three-pattern DNS triage lab

[Triage a Suspicious DNS Case](practice/dns-triage-three-patterns/setup.md): Seventeen-frame explicitly synthetic PTR/SRV/TXT discovery, NXDOMAIN and varied A-query practice with reproducible offline builder, executed checks, separate query/response worksheet fields, evidence-limited key and seven native Linux views.

## Entry, callback and internal activity practice

[Connect Entry, Callback and Internal Activity](materials/stage-20/lesson-2/README.md): Separate synthetic delivery, outbound and internal captures with corroborating records, reproducible offline builder, independent checksum checker, executed CLI results, worksheet and answer guide. Each causal link remains separately assessed; no historical incident or successful access is asserted.

## Updates monitoring and keepalives lab

[Rule Out Updates, Monitoring and Keepalives](practice/rule-out-ordinary-traffic/README.md): 65-frame explicitly synthetic TCP practice with configured update windows, longer monitoring exchanges, actual keepalive probe classifications, offline builder, checked answers and independent native Linux GUI evidence.

## Project 8: Investigate the Unfamiliar Incident

[Project 8: Investigate the Unfamiliar Incident](practice/unfamiliar-incident/README.md): Executable isolated synthetic capstone with outbound and internal leads, benign alternatives, corroborating records, reproducible offline builder, exact executed packet checks, student workbook, separate instructor key and native Linux GUI evidence.

## Unusual DNS names and record types

[Investigate Unusual Names and Record Types](practice/unusual-dns-names-record-types/setup.md): separate synthetic15-frame DNS lab with real TXT question/answer packets, scoped distinct-name verification, safe offline builder, checked answers, four independently reviewed native Linux4.4 views and a separate authorized-capture assignment. Original A-only evidence preserved. Name shapes and TXT records do not identify an original client or establish malicious purpose.

## Reproducible Hunt Workspace profile practice

[Create Your Threat Hunting Profile](materials/stage-2/lesson-3/README.md): Complete offline Hunt Workspace profile exercise, ordered column and coloring definitions, saved TCP/DNS filters, documented time and resolution choices, native ZIP export/import and same-name conflict evidence, synthetic practice capture and safe reproducible builder. Actual Linux settings and transfer versions are recorded; viewing choices do not establish threat findings.

## TCP reassembly and Decode As practice

[Understand Reassembly and Decode As](materials/stage-6/lesson-4/README.md): Complete synthetic26frame segmented HTTP and same-port NOTE control, deterministic offline builder, original packet/sequence arithmetic, actual baseline/override logs, native Wireshark4.4 Linux reassembly tabs and reversible entry workflow, worksheet and checked key. Windows execution and unavailable historical case findings are not asserted.

## Hidden names and payloads lab

[Hunt When Names and Payloads Are Hidden](practice/hidden-flow/README.md): Four explicitly synthetic TLS1.3-over-TCP flows with encrypted exchanges, exact offline reconstruction, executed conversation and timing analysis, worksheet, checked packet key, and independently reviewed native Linux GUI evidence.

## DNS TXT decoding practice

[Examine Synthetic Encoded Training Content](materials/stage-15/lesson-4/README.md): Complete synthetic DNS TXT exercise with a harmless documented Base64 reference, deterministic offline PCAP builder, independent raw parser, actual TShark dissection and native selected-field decoding evidence, worksheet, answer guide and a separate authorized-file assignment. A representation match does not establish encryption, tunneling, exfiltration, process identity or purpose.

## Challenge your own C2 conclusion

[Challenge Your Own C2 Conclusion](materials/stage-16/lesson-5/README.md): Complete synthetic DNS/TCP/TLS-opening packet practice, safe offline builder and independent byte checker, native Linux GUI evidence, three conditional process scenarios, baseline comparison, worksheet and instructor key. Keeps ownership, coverage and hidden application messages explicitly unresolved.

## Direction, Size and Session Reuse

[Compare Direction, Size and Session Reuse](materials/stage-13/lesson-4/README.md): Complete separate synthetic offline lab with three TCP connections, two requests within one reused connection, UDP datagrams, omitted-response and truncated-record derivative, safe deterministic builder, raw checker, native Linux evidence, worksheet and checked results. No historical case or purpose finding is implied.

## Containment verification and recurrence practice

[Verify Containment and Look for Recurrence](materials/stage-21/lesson-5/README.md): Separate fictional pre-action and post-action captures with action and coverage records, safe offline rebuild, independent raw-packet checks, working-copy workflow, worksheet and checked answer guide. Distinguish attempts, established exchanges, control claims and visibility gaps; no historical case or actual enforcement result is claimed.

## HTTP/2, QUIC and HTTP/3 boundary practice

[Recognize HTTP/2, QUIC and HTTP/3 Boundaries](materials/stage-14/lesson-5/README.md): Separate actual owned loopback HTTP/2-over-TLS and HTTP/3-over-QUIC capture, matching disposable lab-only session secrets, two exchanges per connection, before/after visibility checks, verifier, native GUI observations, worksheets and a distinct authorized-file assignment. The lab does not establish original incident or learner-own-capture findings.

## Protocol Hierarchy first-pass triage lab

[Use Protocol Hierarchy for First-Pass Triage](practice/protocol-hierarchy-firstpass/setup.md): Offline synthetic capture, reproducible builder, context CSV, full worksheet, checked hierarchy scope comparison, ICMP packet details and actual native Linux evidence.

## Pivoting and multi-hop investigation practice

[Investigate Pivoting and Multi-Hop Sequences](materials/stage-18/lesson-4/README.md): Separate synthetic A–B and B–C sensor captures, explicit coverage and address assignments, host/session/identity and approved deployment records, safe deterministic rebuild, independent exact packet and scenario checks, actual native GUI evidence, worksheet and answer guide. Packet edges and timing do not prove a causal chain or human identity.

## Visible SMB sessions and operations practice

[Read SMB Sessions and Visible Operations](materials/stage-17/lesson-2/README.md): Actual controlled loopback SMB2 practice with session setup, tree connection, file opens, READ, WRITE and CLOSE, a deliberately shortened window, safe collector, exact checker, actual decoding, worksheet and answer guide. Preserves unknown nonstandard CreateAction5 and missing-response outcomes; does not identify a person or establish an incident.

## Ownership, monitoring and review practice

[Plan Ownership, Monitoring and Review](materials/stage-23/lesson-6/README.md): Separate synthetic DNS fixture and complete handoff worksheet with accepted responsibilities, source and test gates, delivery checks, early-review routing to the proposal owner, documented decisions, and independently accepted visibility-gap work. Includes offline rebuild, actual CLI checks, standard-library handoff validator, rejection evidence and separate authorized-file homework. No operational coverage or original incident findings are claimed.

## TLS decryption expectations lab

[Troubleshoot Decryption Expectations](practice/tls-decryption-expectations/README.md): Five actual controlled Academy loopback TLS exchanges with matching disposable C/D secret logs and RSA certificate key, deliberate missing-start and missing-segment derivatives, exact offline byte replay, checked bounded answers and native Linux GUI evidence.

## Suspicious download investigation lab

[Project 3: The Suspicious Download](practice/suspicious-download/README.md): Synthetic 39-frame HTTP redirect and download case with matching authored endpoint excerpt, verified exports and inert objects, editable investigation workbook, offline builder, checked answers and native Linux evidence.

## Normal Windows network relationships lab

[Establish Normal Windows Network Relationships](practice/windows-normal-relationships/README.md): Explicitly synthetic offline SMB2 Tree Connect packet fixture with executable standard-library builder, contextual CSVs, checked worksheet answers, exact reconstruction and native Linux GUI evidence. No Windows-host or historical-incident capture claim.

## Environment threshold tuning lab

[Tune Thresholds to the Environment](practice/environment-thresholds/README.md): Explicitly synthetic matched role baselines and labelled cases with reproducible offline PCAPs, executed datagram checks, frozen threshold proposal, holdout test, worksheet, checked guide and native Linux GUI evidence.

## Misleading lead and missing evidence lab

[Handle a Misleading Lead and Missing Evidence](practice/misleading-lead-missing-evidence/README.md): Explicitly synthetic two-file UDP evidence-gap practice with offline builder, executed checks, synthetic independent context, conditional real-case notes, checked answers and native Linux GUI evidence.

## Upload directionality lab

[Analyze Upload Patterns and Directionality](practice/upload-directionality/README.md): Synthetic HTTP/FTP and separate actual author-owned encrypted TLS application session, offline builder, exact decoding proofs, worksheet, frame-keyed answers and native Linux GUI evidence.

## Benign and suspicious case testing

[Test Against Benign and Suspicious Cases](materials/stage-23/lesson-4/README.md): Complete synthetic offline five-case exercise with separate PCAPNG originals, immutable proposal, synthetic proxy records, blank matrix, verified packet and log key, deterministic rebuild, actual native Linux supplementary views, and coverage exclusions. Authorization labels are authored context; no historical incident or production performance claim.

## Decision log practice

[Prioritize Anomalies with a Decision Log](materials/stage-7/lesson-6/setup.md): Separate synthetic six-hour and half-hour captures, safe offline rebuild, independent packet checks and native statistics, filters, graph intervals, worksheet and checked key. Packet observations and synthetic context remain distinct; no findings for the unavailable historical case are implied.

## Export fields for a timeline lab

[Export Fields for a Timeline](practice/export-fields-timeline/README.md): Synthetic six-frame DNS export fixture plus separate repeated-A packet fixture, safe executable builders and exports, provenance worksheet, checked answers, real Calc import and native packet evidence.

## Project5 Quiet Callback multi-source lab

[Project5: The Quiet Callback](practice/project5-quiet-callback/README.md): Separate DNS and genuine encrypted TLS sessions in synthetic offline transport, independent host records, approved-agent baseline, reproducible exact reconstruction, checked packet-and-log timeline, and native Linux GUI evidence.

## Color, Comment and Bookmark the Evidence

[Stage 5 Lesson 5](materials/stage-5/lesson-5/README.md): Separate six-frame synthetic offline pcapng lab with safe deterministic generation, pinned verification, native author coloring/marks/filter-bookmark/comment persistence and Displayed versus Captured export evidence, worksheet and answer guide. The author observations use Ubuntu native Wireshark 4.4.0; the Windows 11 learner workflow is explicitly distinguished. Packet observations remain questions rather than incident findings.

## ICMP and unusual-port candidate lab

[Review ICMP and Unusual-Port Candidates](practice/icmp-unusual-port/README.md): Thirty-four-frame explicitly synthetic IPv4/IPv6 Echo, authentic ICMP quoted error, TCP8443/80 and UDP practice with reproducible offline builder, exact executed filter checks, worksheet, checked answer guide and native Linux GUI evidence.

## Project7 download, recurring contact and outbound transfer practice

[Project7: From Suspicious Download to Outbound Transfer](materials/stage-20/lesson-4/README.md): Complete separate offline synthetic edge/internal case: harmless delivery, three distinct status connections, SSH banner exchange, ordinary backup and later sample upload, time-bounded identity mappings, numbered host and business context, explicit observation gap, actual TShark checks, deterministic rebuild and independent checksum checker, bounded native GUI observations, setup, worksheet and answer guide. Chronology does not prove execution, malicious causation or sensitive-data loss.

## Packet citation reproducibility lab

[Make Packet Citations Reproducible](practice/packet-citations/README.md): Synthetic original/derivative citation practice with offline builders, exact byte/time mappings, actual GUI export, worksheet, checked citations and native Linux GUI evidence.

## Weak indicator bounded expansion practice

[Start from a Weak Indicator and Expand Carefully](materials/stage-16/lesson-1/README.md): Complete independent synthetic24frame DNS/TCP/HTTP practice with two A answers, distinct handshake and SYN attempt/retry, bounded Conversations, visible HTTP Follow, an incidental lead and excluded control. Includes dependency-free offline builder, independent checker, actual TShark4.4 evidence, native GUI views, worksheet and answer guide. Packet correlation does not establish process ownership, endpoint control or command-and-control.

## DNS failures, bursts and repeated lookups

[Analyze Failures, Bursts and Repeated Lookups](practice/dns-failure-bursts/README.md): Two separate verified client-facing and upstream synthetic DNS captures with NXDOMAIN, NODATA, SOA and possible retries; independent raw verifier, executed filters, worksheet, evidence-limited answer guide, and native Linux Wireshark 4.6.9 evidence.

## Low-volume and staged transfer practice

[Look for Low-Volume and Staged Transfers](practice/low-volume-staged-transfers/README.md): Separate synthetic sparse-timeline case and actual controlled loopback TLS collection with observed host copy, slice reads and receiver logs, native GUI observations, worksheet and checked answer guide. Host evidence proves this harmless laboratory only; timing and encrypted record lengths alone do not establish file identity, authorization or data loss.

## Discovery followed by authentication activity lab

[Project 4: Discovery Followed by Authentication Activity](practice/project-4-auth-followup/README.md): Separate Academy-designed synthetic discovery/LDAP, Kerberos and NTLMSSP packet fixtures and Windows-shaped identity-event correlation exercise, with executable offline builder, templates, bounded answer key and actual Linux validation. The saved lecture case evidence remains missing.
