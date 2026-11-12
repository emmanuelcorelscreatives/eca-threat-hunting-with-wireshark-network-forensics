# Checker usage — Choose the Durable Behaviour to Monitor

**Stage 23, Lesson 1. Instructor: EMMANUEL CORELS.**

Use the checker to examine the exact synthetic Academy fixture, not to issue a security verdict. The original incident is unavailable. A recurring connection is not proof of malicious activity, intent or a command channel. Inspect only authorized captures. Complete the full `worksheet.md`; checker output does not replace the Conversations, I/O Graphs, underlying-packet or claim-to-source tasks in `setup.md`.

## Optional fail-fast rebuild and read-only check

Use Bash in an authorized kit copy containing the four files below. Python 3 and `sha256sum` are required. This is a **student recipe**, not a recorded learner execution. Each failed integrity check exits immediately, before builder execution. Outputs go to a fresh directory; originals are never builder targets.

```bash
set -euo pipefail
verify_source() {
  local name="$1" expected="$2"
  if [ ! -f "$name" ] || [ ! -r "$name" ]; then
    printf 'Missing or unreadable file: %s\n' "$name" >&2
    exit 1
  fi
  if ! printf '%s  %s\n' "$expected" "$name" | sha256sum --check --status; then
    printf 'SHA-256 mismatch: %s\n' "$name" >&2
    exit 1
  fi
}
verify_source offline-builder.py 287db0760fd6042f4fe0ab58617ccf6df2b9bdc2f1744a1847348a776329a85c
verify_source executed-fixture-spec.json c043f496aa5a4b45ab5819f9267b7426538403072e0f4fffb98e4255271db6e9
verify_source practice.pcap a73bab65f48cc475e2d638181aa8596ba662af89eb2e86c165b3df95d1905e7a
verify_source check_capture.py 266fadee51a03a68de535c3394b9f153797375217b624c13703217339a6f3890
scratch="$(mktemp -d)"
python3 offline-builder.py --spec executed-fixture-spec.json --output "$scratch/practice.pcap"
verify_source "$scratch/practice.pcap" a73bab65f48cc475e2d638181aa8596ba662af89eb2e86c165b3df95d1905e7a
if ! cmp -s -- practice.pcap "$scratch/practice.pcap"; then
  printf 'Fresh capture differs from supplied capture\n' >&2
  exit 1
fi
cp -- check_capture.py executed-fixture-spec.json "$scratch/"
cd -- "$scratch"
verify_source check_capture.py 266fadee51a03a68de535c3394b9f153797375217b624c13703217339a6f3890
verify_source executed-fixture-spec.json c043f496aa5a4b45ab5819f9267b7426538403072e0f4fffb98e4255271db6e9
python3 check_capture.py --capture practice.pcap --spec executed-fixture-spec.json
printf 'Working directory: %s\n' "$scratch"
```

The checker prints JSON and does not modify the capture, build traffic or create an alert. Retain results only under your handling policy. The current builder exclusively creates outputs and refuses existing paths; use another fresh directory rather than replacing an output. `builder-safety-and-rebuild-execution.json` records an actual matching fresh rebuild and both identical-output and different-output refusals with existing files unchanged.

`independent-pcap-execution.json` records the actual raw-check invocation under the private filename `independent-classic-pcap-checker-v2.py`, with the same hash as packaged `check_capture.py`. Do not claim the student command above ran literally. `independent-checker-rejection-proof.json` records four rejected intentionally corrupted scratch copies: bad IP checksum, bad TCP checksum, changed first timestamp and truncated last frame. Originals remained unchanged; students need not recreate those tests.

## Read this fixture's actual report

`independent-pcap-report.json` reports pass for **32 frames**, **1,864 captured packet bytes** and **2,400 physical bytes**. It independently parses existing bytes without importing the builder, compares the actual spec's count, order, timestamps, addresses, ports, flags and payload, and validates included IPv4 and transport checksums. Classic-PCAP accounting is **24 + 32 × 16 + 1,864 = 2,400 bytes**. The first-to-last span is **240.260000 seconds**, from **2025-01-16 09:00:00.000000** to **09:04:00.260000 UTC**. Neither order nor checksum validity proves continuous sensor operation, clock accuracy, authorization or complete collection.

`native-03-properties.png` shows **2,384 bytes** in its native Length counter, alongside 32 packets and 1,864 captured bytes. `native-file-accounting.json` accounts for the 16-byte difference from physical size; do not call it payload or infer truncation.

An **observed start** here is SYN = 1 and ACK = 0 with timestamp, source and peer IPs and ports, raw sequence number and surrounding packets. A same-direction, same-four-tuple, same-raw-sequence retry is not another distinct start. Require the reverse SYN/ACK and asset ACK to call a completed observed handshake; a lone SYN establishes only an attempt.

| UTC on 2025-01-16 | Source → peer | SYN-only / SYN/ACK / ACK frames |
| --- | --- | --- |
| 09:00:00.100000 | `192.0.2.10:54000 → 198.51.100.20:8443` | 3 / 4 / 5 |
| 09:01:00.100000 | `192.0.2.11:55000 → 198.51.100.30:8443` | 10 / 11 / 12 |
| 09:02:00.100000 | `192.0.2.10:54001 → 203.0.113.20:8443` | 19 / 20 / 21 |
| 09:04:00.100000 | `192.0.2.10:54002 → 198.51.100.21:8443` | 26 / 27 / 28 |

The report's distinct observed SYN-start list is **[3, 10, 19, 26]** and its same-tuple raw SYN retry-candidate list is empty. `decoded-fields.stdout.csv`, recorded by `decoded-fields.execution.json`, separately decodes `0x0002`, `0x0012` and `0x0010` for the respective columns above. The earlier `all-frames.stdout.txt` did not export flags; do not retroactively attribute this later check to it.

Frames 3–5 have raw sequence/ACK pairs **(1000, 0)**, **(9000, 1001)** and **(1001, 9001)**. Sequence-end accounting adds TCP payload length plus one for SYN and one for FIN, modulo 2³². All listed ACK checks in this report match prior **observed** reverse sequence ends. This is not proof of complete ACK coverage: unknown prior or outside-file traffic remains unresolved. The report finds no captured HTTP byte origins; every TCP payload length is zero. Do not import HTTP timing or reassembly results from another lesson; this report's `lessonSpecificArithmetic` is empty.

`asset-inventory.csv` defines two review-group workstations. `.10` has three observed starts to changing peers, **120 seconds apart twice**; `.11` has one. Recurrence is not demonstrated for every group member or beyond this short window. Each TCP conversation has seven packets, 378 **frame bytes**, a 0.1600-second observed packet span, and no application bytes. Port 8443 does not identify TLS, an application, a process or purpose.

DNS pairs **1–2** and **17–18** record `check-a.academy.test → 198.51.100.20` and `check-b.academy.test → 203.0.113.20`. Their queries and answers precede the matching peer starts at .100 seconds, but do not prove a process used the answer. There is no captured lookup for peers `198.51.100.30` or `198.51.100.21`; absence here does not establish absence elsewhere. These packets are not independent DNS logs.

## Native evidence is role-limited

Use `native-independent-approvals.json` only for the exact shown states:

- `native-00-file-open.png`: blank read filter. `native-01-unfiltered.png`: blank display filter and 32 packets.
- `native-utc-menu.png`: UTC Date and Time of Day radio selection. `native-utc-applied.png`: unfiltered UTC packet view, not a SYN-filtered timestamp view.
- `native-04-conversations-tcp.png`: TCP · 4, Limit to display filter unchecked; each conversation has 4 asset-to-peer packets / 216 frame bytes and 3 reverse packets / 162 frame bytes. Starts are relative, not UTC. `native-05-endpoints.png` is Ethernet · 7, not IPv4.
- `native-10-filter-01.png`: applied `tcp.flags.syn == 1 && tcp.flags.ack == 0`, showing frames 3, 10, 19 and 26. `native-99-filter-cleared.png`: restored full captured list.
- `native-graph-full-filter-column.png`: enabled All Packets with blank filter, enabled TCP Errors with `tcp.analysis.flags`, 1 sec interval, relative Time (s), Packets/1 sec, Time of day unchecked. All-packet peaks are 9, 7, 9 and 7 near seconds 0, 60, 120 and 240. `one-second-frame-bin-arithmetic.json` is raw-record arithmetic, **not a new GUI observation** or a filtered graph.

Follow the executable native menu instructions in `setup.md` and record your own checks. Peaks can contain multiple packets from one session and DNS; quiet intervals may reflect collection limits. A display filter is not an operational alert. The newly delivered exact-pass native walkthroughs establish expanded details for all 28 TCP frames, four DNS frames, graph-to-packet checks at 60 and 120 seconds, and the recorded Ubuntu host identity. See `native-validation.md` for frame-specific evidence and role limits.

## From observation to candidate

Complete all worksheet fields: capture hash and source, authorization, point/interface, directions, filters/gaps, time window, inventory, packet frames, both ports, distinct-start/retry rule, graph settings, DNS, byte meanings, claim sources, alternatives and evidence requests. Keep observation separate from a question such as: **Do assets in a defined group initiate recurring outbound connections worth reviewing within a known observation window, even if peers change?**

Packet or suitable flow records can support endpoints, ports, protocol, timestamps, direction and volume; flows may omit payload and process. Names need appropriate client/resolver DNS records plus separate evidence of a later connection. Process identity needs endpoint records linking process and connection, not timing alone. Check both-direction coverage, missed segments, short windows, translation/shared services, encryption and preserved surrounding traffic. Approved monitoring, updates, backups and maintenance remain possibilities, not confirmed explanations. No match means only that the source did not show the behaviour under its collection conditions. Narrow the claim or request specific missing records if durability or visibility is uncertain.

Future learner-owned capture work requires permission, a separate collection record and its own hash and frame references; no completed learner is supplied. The original case, independent flow/DNS/endpoint correlation, actual application content, ownership and real coverage remain unavailable. Preserve those unknowns for **Write a Reusable Hunt Playbook**.

## Provenance and review status

`historical-actual-execution-proof.json` is immutable historical evidence, not a current inventory. `source-copy-provenance.json` is an earlier copy record. The supplied `current-kit-inventory.json` binds all final saved guide and evidence bytes; it omits its own hash to avoid recursion. Regenerate it after subsequent changes without altering historical records. Pending statements retained in historical records refer to their older snapshots, not the present builder, decoded-check or native walkthrough status. Complete independent review of the resulting guides remains required before publication. No public placement, verified download, publication, main-course visual/render approval or complete collection coverage is claimed.
