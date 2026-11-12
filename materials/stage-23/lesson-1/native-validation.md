# Native validation — exact saved evidence and walkthrough

**Threat Hunting with Wireshark Course, Stage 23, Lesson 1 — Choose the Durable Behaviour to Monitor. Instructor: EMMANUEL CORELS.**

## Scope

These are saved observations of the separate synthetic Academy `practice.pcap`, SHA-256 `a73bab65f48cc475e2d638181aa8596ba662af89eb2e86c165b3df95d1905e7a`, not the unavailable narrated case. The added walkthrough records actual isolated native GUI actions on this unchanged capture; this documentation revision does not execute the student recipes. `native-independent-approvals.json` binds each delivered PNG to its exact hash, original source and independent receipt. Its approvals are limited to the actual shown state, not the whole lab, lecture, main visuals, render or public placement.

The target is Wireshark 4.4 on Ubuntu 24.04 LTS, English, light theme. `native-host-platform-v6.json` records the actual `/etc/os-release`, `uname` and binary version: Ubuntu 24.04.5 LTS, Linux 6.8.0-51-generic and Wireshark 4.4.0. This machine record is separate from role-limited PNG approval; it does not establish another learner environment.

## What the approved native files establish

| Actual file | Supported observation only |
| --- | --- |
| `native-00-file-open.png` | Native Open Capture File chooser lists practice.pcap as 2.34 KiB with blank Read filter. |
| `native-01-unfiltered.png` | Capture open, empty display filter, 32 packets; standard packet columns and initial DNS frame visible. |
| `native-03-properties.png` | Capture hash, PCAP/Ethernet, 32 packets, 240.260 seconds, 1,864 captured packet bytes, native Length 2,384 bytes. |
| `native-04-conversations-tcp.png` | TCP · 4 selected, Limit to display filter unchecked. Four endpoint/port pairs, each seven packets/378 frame bytes; A → B four packets/216 bytes, B → A three packets/162 bytes; relative starts and 0.1600-second durations. |
| `native-05-endpoints.png` | Ethernet · 7 selected with MAC rows, not IPv4. Limit to display filter unchecked. Do not describe this as an IPv4 Endpoints observation. |
| `native-10-filter-01.png` | Applied `tcp.flags.syn == 1 && tcp.flags.ack == 0`; exactly frames 3, 10, 19, 26, four displayed out of 32. |
| `native-99-filter-cleared.png` | Empty display filter and full 32-packet list restored. |
| `native-utc-menu.png` | Radio dot selects UTC Date and Time of Day. A different highlighted menu row is not the selection indicator. |
| `native-utc-applied.png` | Unfiltered UTC packet list, including frame 1 at 09:00:00.000000, 2 at .020000, 10 at 09:01:00.100000 and 17 at 09:02:00.000000 on 2025-01-16. Not a SYN-filtered UTC screenshot. |
| `native-graph-full-filter-column.png` | All Packets enabled with blank filter; TCP Errors separately enabled with `tcp.analysis.flags`. Interval 1 sec; Time of day unchecked; relative Time (s) axis; Packets/1 sec unit. All-packet peaks 9, 7, 9, 7 near 0, 60, 120, 240 seconds. |

The actual graph does not establish a SYN-filtered graph, another interval, time-of-day axis or hidden setting. `one-second-frame-bin-arithmetic.json` separately assigns frames 1–9, 10–16, 17–25 and 26–32 to those bins. It is raw-record arithmetic, not another GUI observation. DNS contributes to the first and third peaks; peaks are not connection counts. Quiet intervals do not establish collection health or absence of activity elsewhere.

`native-file-accounting.json` and `independent-pcap-report.json` establish physical file size **2,400 bytes = 24 + 32 × 16 + 1,864**. Preserve the actual native Length of 2,384 bytes; do not silently replace it or infer truncation from the known counter difference.

## Independent decoding is separate from native packet-detail inspection

`decoded-fields.stdout.csv`, with execution recorded in `decoded-fields.execution.json`, verifies SYN-only frames 3, 10, 19, 26, reverse SYN/ACK frames 4, 11, 20, 27, and ACK frames 5, 12, 21, 28. `independent-pcap-report.json` separately parses bytes without importing the builder and validates timestamps, count/order, checksums, flags, raw sequences, within-file ACK continuity, retry candidates and HTTP byte origins. It reports no observed same-tuple SYN retry candidates and no HTTP byte origins. All TCP payload lengths are zero. Its ACK checks do not prove coverage outside the captured sequence; unknown prior coverage remains unresolved.

Those results resolve decoded-flag evidence independently of the new native expanded packet-detail observations below. The earlier historical export omitted flags; its original logs remain unchanged. The recorded raw-checker argv used a private original filename, while the matching delivered copy is `check_capture.py`. No literal execution of a student recipe is inferred.

## Reproduce the recorded native exercise

Perform these steps on an authorized working copy, as an ordinary user; record your own results rather than attributing them to the saved screenshots:

1. Record capture filename, path, SHA-256, permission and handling limits, provider, observation point/interface, filters, clock/time zone, drops/gaps, inventory and ownership source. A read-only local hash command is `sha256sum -- practice.pcap`. Do not overwrite the original.
2. In **File → Open**, leave Read filter blank. Clear the display-filter bar. Select **View → Time Display Format → UTC Date and Time of Day** and check the radio selection and actual Time column.
3. Open **Statistics → Conversations**, select **TCP** and record Limit to display filter state. Record each source and peer IP and port, direction, relative start, duration and directional frame counts/bytes. Do not treat frame bytes as payload.
4. Apply `tcp.flags.syn == 1 && tcp.flags.ack == 0`. Inspect each match's four-tuple and raw sequence for retry treatment. Clear the filter, select frames 3–5, 10–12, 19–21 and 26–28, and expand **Internet Protocol Version 4** and **Transmission Control Protocol** in Packet Details. Record flags, direction, raw sequence/ACK and zero payload; distinguish GUI-relative sequence numbers from raw values. Inspect closure and surrounding DNS frames as context. A lone SYN is an attempt; require the reverse SYN/ACK and following ACK for an observed handshake.
5. Open **Statistics → I/O Graphs**. Record enabled rows, full filters, interval, time reference and unit. Select a candidate time window, return to the packet list and inspect the corresponding exchanges and surrounding traffic. Record which frames substantiate the interpretation. The recorded 60- and 120-second walkthrough below supplies graph hints and corresponding selected underlying packets. A graph screenshot alone does not supply the packet details.
6. Record what the window and collection cannot establish. Keep observation, candidate interpretation and unknowns separate. No filter can recover uncollected packets or become an operational alert merely by being applied.

Use the full tables and source-matching questions in `worksheet.md`; compare packet answers in `answer-guide.md`. For a future learner-owned capture, obtain authorization before collection or inspection, preserve an untouched original where allowed, complete a separate collection record and repeat these checks using its own frames and ports. No learner-owned investigation has been supplied or completed here.

## Evidence limits and release boundary

- Author native packet-detail, graph-window-to-packet and host-platform records are now supplied below. Keep their exact scope; no hidden preference action or 240-second graph-click success is claimed.
- Preserve `historical-actual-execution-proof.json` unchanged. The supplied `current-kit-inventory.json` binds all final saved guides and evidence members, intentionally excluding its own recursive hash. Refresh after subsequent changes.
- Keep the original case unavailable. Request suitable authorized packet/flow, DNS, endpoint, inventory, owner and observation-point records before making claims beyond this synthetic file. A lookup alone does not prove a later connection; timing alone does not identify a process; port 8443 does not prove TLS. Approved monitoring, updates, backups and maintenance are unconfirmed alternatives.
- Require a separate complete independent review of every resulting guide before publication. No verified public download, publication, main-course visual or render approval is claimed.


## Recorded packet-by-packet native inspection

`native-walkthrough-source-provenance.json` binds the raw capture sessions and their source SHA-256. `native-independent-approvals.json` binds each delivered PNG to its original immutable review receipt SHA and verbatim role-limited verdict. All added PNGs have exact independent PASS; held screenshots are excluded. `practice.pcap` remains the original 2,400-byte synthetic fixture. No live collection or learner-owned investigation occurred.

Clear the display filter. Use **Go → Go to Packet** to select each original frame, then open its Packet Details (double-click or **View → Show Packet in New Window**). Expand **Internet Protocol Version 4** and **Transmission Control Protocol**. The delivered `native-v6-packet-NN.png` files record every TCP frame, including handshake and closure, with visible raw-valued sequence/ACK, flags, direction and zero TCP segment length. No preference-menu success is inferred from a keyboard action: the values themselves match independently decoded raw values. Native checksum fields are shown as unverified; validated checksums come from the separate byte checker, not from that GUI status.

| Exchange | Initiating tuple | Handshake frames | Closure-context frames | Delivered frame views |
| --- | --- | --- | --- | --- |
| 0 | 192.0.2.10:54000 → 198.51.100.20:8443 | 3,4,5 | 6–9 | native-v6-packet-03.png through native-v6-packet-09.png |
| 1 | 192.0.2.11:55000 → 198.51.100.30:8443 | 10,11,12 | 13–16 | native-v6-packet-10.png through native-v6-packet-16.png |
| 2 | 192.0.2.10:54001 → 203.0.113.20:8443 | 19,20,21 | 22–25 | native-v6-packet-19.png through native-v6-packet-25.png |
| 3 | 192.0.2.10:54002 → 198.51.100.21:8443 | 26,27,28 | 29–32 | native-v6-packet-26.png through native-v6-packet-32.png |

The following values are copied from this capture's independently executed `decoded-fields.stdout.csv` and agree with the exact native review observations. Direction is explicit; ACK/sequence values are raw, not GUI-relative sequence numbers. Every listed segment has zero TCP application bytes.

| Frame | Source IP:port → destination IP:port | Flags | Raw sequence | Raw ACK | TCP length |
| --- | --- | --- | --- | --- | --- |
| 3 | 192.0.2.10:54000 → 198.51.100.20:8443 | 0x0002 | 1000 | 0 | 0 |
| 4 | 198.51.100.20:8443 → 192.0.2.10:54000 | 0x0012 | 9000 | 1001 | 0 |
| 5 | 192.0.2.10:54000 → 198.51.100.20:8443 | 0x0010 | 1001 | 9001 | 0 |
| 6 | 192.0.2.10:54000 → 198.51.100.20:8443 | 0x0011 | 1001 | 9001 | 0 |
| 7 | 198.51.100.20:8443 → 192.0.2.10:54000 | 0x0010 | 9001 | 1002 | 0 |
| 8 | 198.51.100.20:8443 → 192.0.2.10:54000 | 0x0011 | 9001 | 1002 | 0 |
| 9 | 192.0.2.10:54000 → 198.51.100.20:8443 | 0x0010 | 1002 | 9002 | 0 |
| 10 | 192.0.2.11:55000 → 198.51.100.30:8443 | 0x0002 | 4000 | 0 | 0 |
| 11 | 198.51.100.30:8443 → 192.0.2.11:55000 | 0x0012 | 12000 | 4001 | 0 |
| 12 | 192.0.2.11:55000 → 198.51.100.30:8443 | 0x0010 | 4001 | 12001 | 0 |
| 13 | 192.0.2.11:55000 → 198.51.100.30:8443 | 0x0011 | 4001 | 12001 | 0 |
| 14 | 198.51.100.30:8443 → 192.0.2.11:55000 | 0x0010 | 12001 | 4002 | 0 |
| 15 | 198.51.100.30:8443 → 192.0.2.11:55000 | 0x0011 | 12001 | 4002 | 0 |
| 16 | 192.0.2.11:55000 → 198.51.100.30:8443 | 0x0010 | 4002 | 12002 | 0 |
| 19 | 192.0.2.10:54001 → 203.0.113.20:8443 | 0x0002 | 2000 | 0 | 0 |
| 20 | 203.0.113.20:8443 → 192.0.2.10:54001 | 0x0012 | 10000 | 2001 | 0 |
| 21 | 192.0.2.10:54001 → 203.0.113.20:8443 | 0x0010 | 2001 | 10001 | 0 |
| 22 | 192.0.2.10:54001 → 203.0.113.20:8443 | 0x0011 | 2001 | 10001 | 0 |
| 23 | 203.0.113.20:8443 → 192.0.2.10:54001 | 0x0010 | 10001 | 2002 | 0 |
| 24 | 203.0.113.20:8443 → 192.0.2.10:54001 | 0x0011 | 10001 | 2002 | 0 |
| 25 | 192.0.2.10:54001 → 203.0.113.20:8443 | 0x0010 | 2002 | 10002 | 0 |
| 26 | 192.0.2.10:54002 → 198.51.100.21:8443 | 0x0002 | 3000 | 0 | 0 |
| 27 | 198.51.100.21:8443 → 192.0.2.10:54002 | 0x0012 | 11000 | 3001 | 0 |
| 28 | 192.0.2.10:54002 → 198.51.100.21:8443 | 0x0010 | 3001 | 11001 | 0 |
| 29 | 192.0.2.10:54002 → 198.51.100.21:8443 | 0x0011 | 3001 | 11001 | 0 |
| 30 | 198.51.100.21:8443 → 192.0.2.10:54002 | 0x0010 | 11001 | 3002 | 0 |
| 31 | 198.51.100.21:8443 → 192.0.2.10:54002 | 0x0011 | 11001 | 3002 | 0 |
| 32 | 192.0.2.10:54002 → 198.51.100.21:8443 | 0x0010 | 3002 | 11002 | 0 |

For surrounding DNS context inspect `native-v4-packet-01.png`, `native-v4-packet-02.png`, `native-v4-packet-17.png` and `native-v4-packet-18.png`. These show the two client/resolver A query/reply pairs. Match names and answers to the DNS table in `answer-guide.md`, then compare later SYN frames 3 and 19. Captured DNS packets are not independent DNS logs or process attribution. A DNS lookup alone does not prove a subsequent connection.

## Recorded graph-window-to-packet walkthrough

1. Clear the display filter, open **Statistics → I/O Graphs**, select enabled **All Packets**, with a blank filter and **Packets** Y axis. Set **Interval: 1 sec**; keep **Time of day** unchecked so **Time (s)** is capture-relative. The separately enabled **TCP Errors** row has filter `tcp.analysis.flags`; it does not change the All Packets series. `native-v4-graph-00-full-settings.png` records these settings.
2. Hover the relative 60-second peak until the hint reads **Click to select packet 16 (60s = 7)**. `native-v6-graph-selected-60.png` records the hint. Click the target and return to the main packet view: `native-v6-graph-to-packet-60.png` records selected original frame 16, relative 60.260000, 192.0.2.11:55000 → 198.51.100.30:8443, ACK, raw Seq 4002, Ack 12002, Len 0. The hover image alone is not proof of selection; the separate selected-packet image records the resulting state, and raw capture actions provide the session history.
3. Repeat at relative 120 seconds: hint **Click to select packet 25 (120s = 9)** in `native-v6-graph-selected-120.png`; selected frame 25 in `native-v6-graph-to-packet-120.png` is at relative 120.260000, 192.0.2.10:54001 → 203.0.113.20:8443, ACK, raw Seq 2002, Ack 10002, Len 0. The selected closure packet is not itself a fresh connection start; inspect frames 19–21 to confirm the handshake.
4. To inspect each whole supporting window independently of the graph click, close the graph and apply `frame.time_relative >= 60 && frame.time_relative < 61`, then the equivalent 120–121 window. Use the exact-pass `native-v4-window-60.png` and `native-v4-window-120.png` where named in the approval ledger. The 60-second window contains frames 10–16 (one seven-frame TCP exchange); the 120-second window contains frames 17–25 (two DNS packets and seven TCP frames). Clear the filter afterward and check the 32-packet status.
5. `native-v5-graph-bin-60.png`, `native-v5-graph-bin-120.png` and `native-v5-graph-bin-240.png` separately establish hints of 7,9,7 packets in one-second bins at 60,120,240 seconds. The 240-second window contains frames 26–32; no successful 240-second graph-to-packet click is claimed or delivered. Do not use failed 239-second hint images. Relative 0-second bin membership (frames 1–9) is supported by separate arithmetic and the existing full graph, without claiming a newly passed bin-zero hover.

These are one-second bins **at** relative 60 and 120 seconds, not graph intervals of 60 or 120 seconds. Counts are packets, not connections: DNS and TCP closure contribute. Selected frames 16 and 25 are final ACKs, not first SYNs. Verify original frame IDs and inspect all supporting exchanges rather than treating a peak as a distinct start. Quiet bins, the synthetic first-to-last window, and these scoped GUI checks cannot establish real collection completeness, process identity or intent.
