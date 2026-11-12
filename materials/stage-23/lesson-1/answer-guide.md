# Checked answer guide — Choose the Durable Behaviour to Monitor

**Threat Hunting with Wireshark Course, Stage 23, Lesson 1. Instructor: EMMANUEL CORELS.**

## Evidence boundary

`practice.pcap` is separate synthetic Academy coursework, not the unavailable narrated incident or a finding about production traffic. Inspect only authorized captures. Keep packet observations, interpretation and unknowns separate. The lecture is unchanged; its next lesson is **Write a Reusable Hunt Playbook**.

The capture SHA-256 is `a73bab65f48cc475e2d638181aa8596ba662af89eb2e86c165b3df95d1905e7a`. `executed-fixture-spec.json` is authored deterministic input, not independent collection evidence; `fixture-spec.json` is its byte-identical supplied alias. `builder-safety-and-rebuild-execution.json` records a fresh matching rebuild using the current exclusive-creation builder and refusals to replace both identical and different existing outputs. No originals were overwritten.

The later `decoded-fields.execution.json` and `decoded-fields.stdout.csv` supply the previously missing decoded flags. `independent-pcap-execution.json` and `independent-pcap-report.json` record a separate raw-byte parser that did not import the builder. The recorded checker invocation used `independent-classic-pcap-checker-v2.py`; the supplied copy is `check_capture.py`, with matching checker hash. Student recipes are not transcripts of those original arguments. This documentation revision executes nothing.

`historical-actual-execution-proof.json` remains an immutable historical snapshot, including its older builder and prose hashes and then-pending GUI status. It is not a current inventory. The supplied `current-kit-inventory.json` binds these final saved guide and evidence bytes and intentionally excludes its own recursive hash. Separate complete independent review is required before publication; regenerate the inventory if files subsequently change.

## Counts, time and byte meanings

`capture-info.stdout.txt` reports Ethernet PCAP with microsecond file precision, **32 packets**, **2,400 file bytes**, **1,864 recorded frame bytes** and a **240.260000-second** first-to-last span. Frames 1 and 32 in `all-frames.stdout.txt` explicitly establish UTC endpoints of **2025-01-16 09:00:00.000000** and **09:04:00.260000**, with epoch seconds `1737018000.000000000` and `1737018240.260000000`. `frame.time_utc` is human-readable UTC, not ISO 8601; `frame.time_epoch` is decimal epoch seconds. The pinned build does not support `frame.time_iso8601`.

`protocol-hierarchy.stdout.txt` records 32 Ethernet/IPv4 frames totaling 1,864 frame bytes: four UDP/DNS frames totaling 352 bytes and 28 TCP frames totaling 1,512 bytes. Every TCP frame is 54 bytes with `tcp.len` equal to 0 and blank payload. Exported HTTP fields are blank. Frame bytes are not TCP application bytes, transferred files or HTTP response sizes.

Each TCP conversation has seven frames and 378 frame bytes: four asset-to-peer frames/216 bytes and three peer-to-asset frames/162 bytes. Its observed packet span is 0.1600 seconds (`tcp-conversations.stdout.txt`). Starts in that table are relative to frame 1, not UTC.

`native-03-properties.png` shows a native Length of **2,384 bytes**, not the filesystem size of 2,400 bytes. `native-file-accounting.json` reconciles this exact file: **24 + 32 × 16 + 1,864 = 2,400 bytes**. The known native counter difference is not evidence of truncation. Neither the first-to-last span nor scripted two-way exchanges proves continuous real sensor coverage.

## Accepted events and checked packet answers

For this exercise, an observed initiating SYN has **SYN = 1 and ACK = 0**, a timestamp, an inventory-group source IP and port, and a scoped peer IP and destination port. Inspect four-tuples and raw sequences: a same-direction, same-four-tuple, same-raw-sequence SYN retry is not another distinct start. A lone SYN supports an attempt, not a completed handshake. Require the reverse SYN/ACK and subsequent asset ACK on the same tuple to describe an observed completed handshake. Do not count graph peaks, closure packets or ACKs as starts.

The following times are UTC on **2025-01-16**, from `all-frames.stdout.txt` and `decoded-fields.stdout.csv`:

| Asset | SYN frame and UTC | Source → peer; stream | Raw initial sequence | SYN/ACK; ACK | Remaining closure frames | Relative start |
| --- | --- | --- | --- | --- | --- | --- |
| LAB-WS-01 | 3; 09:00:00.100000 | `192.0.2.10:54000 → 198.51.100.20:8443`; 0 | 1000 | 4; 5 | 6–9 | 0.100000 s |
| LAB-WS-02 | 10; 09:01:00.100000 | `192.0.2.11:55000 → 198.51.100.30:8443`; 1 | 4000 | 11; 12 | 13–16 | 60.100000 s |
| LAB-WS-01 | 19; 09:02:00.100000 | `192.0.2.10:54001 → 203.0.113.20:8443`; 2 | 2000 | 20; 21 | 22–25 | 120.100000 s |
| LAB-WS-01 | 26; 09:04:00.100000 | `192.0.2.10:54002 → 198.51.100.21:8443`; 3 | 3000 | 27; 28 | 29–32 | 240.100000 s |

The later decoded CSV verifies SYN-only `0x0002` at frames **3, 10, 19, 26**, SYN/ACK `0x0012` at **4, 11, 20, 27**, and ACK `0x0010` at **5, 12, 21, 28**. Each seven-frame exchange has flags S, SA, A, FA, A, FA, A. These are now decoded results, not merely scripted spec values. The older `all-frames.stdout.txt` did not export flags or checksum status; preserve that distinction.

For example, frames 3–5 have raw sequence/ACK pairs **(1000, 0), (9000, 1001), (1001, 9001)**. The other SYN/ACK initial sequences are 12000, 10000 and 11000 respectively. Wireshark may display relative sequence numbers; do not copy relative 0 or 1 into a raw-sequence field.

The independent report validates count, order, timestamps, included IPv4 and transport checksums, flags and raw sequences against the spec. It lists distinct observed SYN starts **[3, 10, 19, 26]**, no observed same-tuple raw SYN retry candidates, and no captured HTTP byte origins. Its 24 listed ACK continuity checks match earlier observed reverse-sequence ends. This is within-file evidence, not proof of unseen traffic or complete prior ACK coverage; unknown coverage outside these matches remains unresolved. The empty `_ws.malformed` selection in `malformed.stdout.txt` alone proves neither checksums nor completeness. Saved root warnings describe historical executions, not recommended privileges.

LAB-WS-01 has three observed starts to changing peers, separated by **120 seconds twice**. LAB-WS-02 has one observed start: recurrence is not demonstrated for every group member. This short scripted spacing does not establish a longer operating cycle.

## DNS answers

| Frames | Client and resolver | Captured query and A answer | Query / answer UTC | Later matching peer |
| --- | --- | --- | --- | --- |
| 1–2 | `192.0.2.10:53100 ↔ 192.0.2.53:53` | `check-a.academy.test`; `198.51.100.20` | 09:00:00.000000 / .020000 | Frame 3 at .100000 |
| 17–18 | `192.0.2.10:53101 ↔ 192.0.2.53:53` | `check-b.academy.test`; `203.0.113.20` | 09:02:00.000000 / .020000 | Frame 19 at .100000 |

These type A queries, answers and ordering are decoded in `all-frames.stdout.txt` and `decoded-fields.stdout.csv` and independently parsed in `independent-pcap-report.json`. They do not prove a process used an answer. There is no captured lookup for peers `198.51.100.21` or `198.51.100.30`; absence here does not prove none happened elsewhere. The resolver IP conversation aggregates four frames/352 frame bytes across **120.0200 seconds**, spanning two DNS exchanges, not one continuous lookup (`ip-conversations.stdout.txt`). Captured DNS packets are not independent DNS logs.

## Native evidence and recorded GUI walkthrough

See `native-validation.md` for the exact role-limited screenshot evidence. Saved native views establish Conversations, the applied SYN-only filter and its clearing, UTC display, and the particular unfiltered one-second All Packets graph. New exact-pass views expand all 28 TCP frames, show the four DNS frames, and trace graph bins at 60 and 120 seconds to selected underlying packets. `native-host-platform-v6.json` records Ubuntu 24.04.5 LTS and Wireshark 4.4.0. See the frame-specific walkthrough in `native-validation.md`; no 240-second graph-click success is claimed.

## Defensible candidate and source matching

An indicator is a specific peer such as `198.51.100.20` at frame 3 or the domain at frame 1. A durable candidate is a question: **For inventory-defined review-lab-workstations, which assets initiate distinct outbound TCP connections repeatedly within a defined, adequately covered window, regardless of peer address, warranting contextual review?** Specify the intended repetition threshold, ports, direction, source fields and review period rather than silently turning fixture spacing into a production rule. Changing a peer should not erase the question. A display filter is not an operational alert.

`asset-inventory.csv` supplies authored workstation roles and group membership, not discovered ownership or processes; the resolver is outside the group. `executed-fixture-spec.json` describes a synthetic lab-segment link, not measured coverage.

For broader connection claims, request packet, connection or network-flow records covering the intended group, observation points and window, with endpoints, both ports, protocol, timestamps and needed direction/volume. Flows can omit full payload and process identity. For names, request suitable DNS logs identifying client or resolver, query, answer and time, plus separate network evidence of the later connection. For initiating software, require endpoint records linking a process to its connection; timing alone is insufficient. Visible application-content claims require a suitable authorized capture, and protected messages additionally require appropriate authorized secrets. This file has no TCP application payload or HTTP/TLS exchange; **port 8443 does not prove TLS**.

Approved monitoring, updates, backups and maintenance remain possible, not confirmed, explanations. Ownership, authorization, initiating process, intent, real collection gaps, missed segments, NAT/shared-service attribution and longer cycles remain unknown. A no-match result means only that this source did not show the behaviour under its collection conditions. Narrow or hold claims when telemetry cannot show them, and request the specific missing observation point or record. Keep original-investigation references unresolved and separate: no original case was supplied.

For future learner-owned work, arrange permission and handling limits first; preserve an untouched original where allowed and analyse a working copy. Complete the worksheet's separate collection record with filename, SHA-256, provider, interface, filters, drops/gaps, clock/time zone, observed times, inventory and owners. Repeat native inspection using that capture's own frames and ports. This is future learner work, not a completed investigation supplied by this kit.
