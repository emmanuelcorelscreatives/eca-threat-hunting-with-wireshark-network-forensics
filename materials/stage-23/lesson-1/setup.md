# Choose the durable behaviour — supplemental offline kit

**Stage 23, Lesson 1. Instructor: EMMANUEL CORELS.**

## Scope and prerequisites

This unpublished kit is **synthetic Academy coursework**. `practice.pcap` is not the unavailable narrated incident, production traffic or evidence of malicious activity. Inspect only authorized captures. The unchanged lesson asks you to choose durable, peer-independent behaviour your telemetry can show, without treating recurring communication as a verdict.

Use an authorized working copy. The course target is **Wireshark 4.4 on Ubuntu 24.04 LTS, English, light theme**. Saved CLI execution uses pinned native Linux 4.4.0 tools. `native-host-platform-v6.json` records the actual Ubuntu 24.04.5 LTS host, kernel and Wireshark 4.4.0 binary used for the isolated GUI walkthrough; individual PNG approvals remain limited to visible actions. Run local analysis tools as an ordinary user; saved TShark root warnings describe historical execution, not recommended privileges. Python 3's standard library is sufficient for the optional offline builder and checker; neither sends packets.

`asset-inventory.csv` assigns `LAB-WS-01` (`192.0.2.10`) and `LAB-WS-02` (`192.0.2.11`) to `review-lab-workstations`; `LAB-RESOLVER-01` (`192.0.2.53`) is outside that group. Roles are authored metadata, not discovered processes, owners or approvals. `executed-fixture-spec.json` names a synthetic lab-segment link, not measured sensor coverage. `fixture-spec.json` was byte-identical at assembly, not an independent source. Prefer the executed spec if aliases later differ.

## Preserve evidence and verify identity

Read-only identity check:

```sh
sha256sum -- practice.pcap
```

Expected SHA-256: `a73bab65f48cc475e2d638181aa8596ba662af89eb2e86c165b3df95d1905e7a`.

Do not overwrite originals. Rebuilding is optional; use the fail-fast hash checks and fresh-output recipe in [checker-usage.md](checker-usage.md). The **current** `offline-builder.py` requires `--spec` and `--output`, uses exclusive creation and refuses existing outputs. `builder-safety-and-rebuild-execution.json` records an actual fresh matching rebuild and refusals for both identical and different existing outputs, with those files unchanged. Earlier statements that this builder overwrites describe an older version and are superseded by that evidence.

Student recipes are not literal execution transcripts. `historical-actual-execution-proof.json` preserves the original argv, older builder identity, older prose hashes and then-pending status. Do not edit it into a current manifest. `source-copy-provenance.json` records an earlier copy snapshot. The supplied `current-kit-inventory.json` binds the final saved guide and evidence files, excluding its own recursive hash. Refresh it only after subsequent changes.

Old draft `build_fixture.py` commands, the unpublished `materials/stage-23/lesson-01/` location and `durable-behaviour-supplemental.pcap` alias were not executed as documented or supplied as verified downloads. They are not required duplicate artifacts. Use the actual packaged filenames.

## What the saved checks establish

`capture-info.stdout.txt` and `independent-pcap-report.json` establish **32 packets**, **2,400 physical file bytes**, **1,864 captured frame bytes**, microsecond classic Ethernet PCAP timestamps, and a **240.260000-second** first-to-last span. `all-frames.stdout.txt` explicitly places frames 1 and 32 at **2025-01-16 09:00:00.000000 UTC** and **09:04:00.260000 UTC**. This is not proof of continuous collection.

The original all-frame export omitted flags and checksum status. The later `decoded-fields.execution.json` and `decoded-fields.stdout.csv` supply independently decoded flags and checksum-status fields. `independent-pcap-execution.json` and `independent-pcap-report.json` separately parse raw bytes without importing the builder, validating count, order, times, included checksums, flags, sequence ends, ACK relationships, retry candidates and HTTP byte origins. A pass establishes agreement with this synthetic spec, not real-world coverage or authorization. The empty `malformed.stdout.txt` selection alone would not validate checksums.

Observed SYN-only frames are **3, 10, 19, 26**; reverse SYN/ACK frames are **4, 11, 20, 27**; subsequent asset ACK frames are **5, 12, 21, 28**. There are no observed same-tuple, same-raw-sequence SYN retry candidates. Listed ACKs match prior observed reverse sequence ends; unknown prior or outside-file ACK coverage remains unresolved.

## Native workflow — perform and record your own observations

1. Choose **File → Open**, open your working copy of `practice.pcap`, and leave **Read filter** blank. Clear the display-filter bar. Use **Statistics → Capture File Properties** to inspect capture identity, counts and times. `native-00-file-open.png` and `native-01-unfiltered.png` establish only their blank-filter/opened-file states.
2. Choose **View → Time Display Format → UTC Date and Time of Day**. Verify the radio dot, not a highlighted row. `native-utc-menu.png` records that selection; `native-utc-applied.png` is an **unfiltered** UTC packet list, not a SYN-filtered view. `frame.time_utc` in the CLI export is human-readable UTC, not ISO 8601; `frame.time_epoch` is epoch seconds. The pinned build does not support `frame.time_iso8601`.
3. Choose **Statistics → Conversations**, select **TCP**, and record whether **Limit to display filter** is unchecked. Inspect endpoint IPs and ports, both directions, relative starts and durations. `native-04-conversations-tcp.png` shows TCP · 4, four conversations, each with **7 packets / 378 frame bytes**, split **4 / 216** asset to peer and **3 / 162** back, with **0.1600-second** observed duration. Conversation starts are relative, not UTC. `native-05-endpoints.png` shows **Ethernet · 7**, not IPv4 Endpoints.
4. Apply `tcp.flags.syn == 1 && tcp.flags.ack == 0` in the display-filter bar and press Enter. `native-10-filter-01.png` records exactly frames 3, 10, 19 and 26. Clear the filter to recover surrounding captured traffic; `native-99-filter-cleared.png` records the restored 32-packet list. A display filter is not an alert and cannot recover uncollected packets.
5. Select the listed frames and follow-ups, expanding **Internet Protocol Version 4** and **Transmission Control Protocol** in Packet Details. Record IPs, both ports, flags, raw sequence and ACK values and directions. Use `tcp.seq_raw` and `tcp.ack_raw` from the exports rather than copying GUI-relative sequence numbers as raw values. A distinct observed start requires SYN = 1, ACK = 0, timestamp and scoped four-tuple; exclude same-direction, same-tuple, same-raw-sequence retries. Require the reverse SYN/ACK and asset ACK before describing a completed observed handshake. ACKs, closures and graph peaks are not additional starts.
6. Choose **Statistics → I/O Graphs**. Record enabled rows, full filters, interval, time reference and units. The approved `native-graph-full-filter-column.png` shows enabled **All Packets** with a blank filter and **TCP Errors** with `tcp.analysis.flags`, **1 sec**, relative **Time (s)**, **Packets/1 sec**, and Time of day unchecked. All-packet peaks are **9, 7, 9, 7** near **0, 60, 120, 240 seconds**. Do not claim a SYN-filtered graph or hidden setting. `one-second-frame-bin-arithmetic.json` independently groups raw timestamps into frames 1–9, 10–16, 17–25 and 26–32; it is arithmetic, not another GUI observation.
7. Choose a graph window, return to the packet list and inspect the underlying tuples and exchanges. Clear temporary filters and inspect surrounding DNS, handshake and teardown packets. A peak includes multiple packets and sometimes DNS; quiet intervals can reflect collection limits. Apply `dns` temporarily to inspect pairs 1–2 and 17–18, then clear it.

`native-independent-approvals.json` limits approval to those exact shown states. New independently passed views establish expanded Packet Details for all four handshakes and their closures, all four DNS frames, and graph-window-to-packet checks at 60 and 120 seconds. Follow `native-validation.md` to reproduce these exact checks and record your own observations. No 240-second graph-click success is claimed.

## Interpret and extend carefully

For `.10`, SYN starts at 09:00:00.100000, 09:02:00.100000 and 09:04:00.100000 UTC are **120 seconds apart twice**, to changing peers. `.11` has one observed start, not demonstrated recurrence. These short scripted observations do not establish a longer cycle or recurrence for every group member.

Every TCP `tcp.len` is zero. The 54-byte TCP frames and 378-byte conversation totals are frame bytes, not application data. `protocol-hierarchy.stdout.txt` records **4 DNS frames / 352 frame bytes** and **28 TCP frames / 1,512 frame bytes**. The raw report has no captured HTTP byte origins. Port 8443 does not establish TLS, encrypted content, HTTP or an initiating process. `native-03-properties.png` shows native Length **2,384 bytes**, not the physical **2,400 bytes**; `native-file-accounting.json` reconciles physical size as **24 + 32 × 16 + 1,864 = 2,400**. Do not infer truncation from that UI counter difference.

Complete every field and task in `worksheet.md`. Match connection claims to suitable packet/connection or flow records, names to relevant DNS records plus separate later-connection evidence, and software to endpoint records linking process and connection—not timing alone. Flows may omit payload and process identity. Protected content requires a suitable authorized capture and authorized secrets. Independent flow/DNS logs, endpoint records, ownership and approval evidence are not supplied.

For future learner-owned work, arrange permission and handling limits first; preserve an original where permitted and record a separate capture hash, provider, interface, observation point, clock/time zone, filters, loss/gaps, UTC window, directions, inventory and supporting frames. Check visibility of both directions, missing segments, short windows, NAT/shared services and encryption. Consider approved updates, monitoring, backups and maintenance as unconfirmed alternatives. No match means only that this source did not show the behaviour under its collection conditions. Request the specific missing observation point or record, or narrow the candidate. Preserve original-case unknowns; the original case remains unavailable. The next lesson is **Write a Reusable Hunt Playbook**.
