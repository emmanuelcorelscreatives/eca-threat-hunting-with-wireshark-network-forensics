# Checked answer guide — Protocol Hierarchy first-pass triage

This is a separate original Academy synthetic companion lab, not the unavailable case pack in the unchanged lecture. Match `practice.pcap` SHA-256 `e10afad728c59c439fda842c80ef7b18f366c20922299ea3919b558f2ac09337` before applying frame references. The capture is 1,008 file bytes, 808 captured frame bytes, 11 frames and 0.420000 seconds from 2025-01-16 12:00:00.000000 UTC through 12:00:00.420000 UTC. Capture point and asset roles in `capture-context.csv` are authored scenario context, not independently observed ownership. Nothing here supplies the original case's percentages, packets, user or incident finding.

## Checked native GUI scope comparison

These observations were recorded in native Linux Qt Wireshark 4.4.0 on Ubuntu 24.04.5 LTS, not Windows. `native-01-hierarchy-unfiltered.png` and `native-06-reopened-unfiltered.png` show `No display filter.` at the bottom. The actual GUI values are:

| GUI row | Packets | Percent Packets | Bytes | End Packets | PDUs |
| --- | ---: | ---: | ---: | ---: | ---: |
| Frame | 11 | 100.0 | 808 | 0 | 11 |
| Ethernet | 11 | 100.0 | 154 | 0 | 11 |
| Internet Protocol Version 4 | 11 | 100.0 | 220 | 0 | 11 |
| User Datagram Protocol | 6 | 54.5 | 48 | 0 | 6 |
| Domain Name System | 6 | 54.5 | 266 | 6 | 6 |
| Transmission Control Protocol | 3 | 27.3 | 60 | 3 | 3 |
| Internet Control Message Protocol | 2 | 18.2 | 60 | 2 | 2 |

`native-02-icmp-filter.png` shows the accepted `icmp` filter and frames 10 and 11. After closing and reopening Protocol Hierarchy, `native-03-hierarchy-icmp.png` shows `Display filter: icmp`. Its Frame, Ethernet, IPv4 and ICMP rows each show 2 Packets, 100.0 Percent Packets and 2 PDUs. Their Bytes are respectively 128, 28, 40 and 60. End Packets is 0 for Frame/Ethernet/IPv4 and 2 for ICMP. Clearing the display filter and reopening restored the 11-frame hierarchy above. An existing open window is not a new scope measurement.

These GUI Bytes are protocol-row measures. The older CLI `protocol-hierarchy.stdout.txt` logs cumulative frame-byte counts: eth/ip 11/808, udp/dns 6/518, tcp 3/162 and icmp 2/128. Do not copy those CLI bytes into GUI Bytes cells. The PCAP file size, captured frame bytes, protocol bytes and application content are different measures. Packets can count at multiple decoded layers; percentages are not additive slices. End Packets counts packets ending dissection at that layer. PDUs count protocol data units and can outnumber packets in other captures; this small fixture happens to show equal Packets and PDUs. Child rows need not sum to parents because of overhead, reassembly or undecoded higher layers. A protocol label does not identify distinct software or establish authorization.

## Checked packet evidence and decoder results

`native-packet-10.png` shows actual selected original frame 10, 64 bytes, `192.0.2.10 → 192.0.2.1`, ICMP Type 8 Echo request, Code 0, Identifier (BE) 300, Sequence Number (BE) 1, and checksum status Good. The LE interpretations differ; report the BE fields named here. The bracketed response-frame link to 11 is generated analysis, not a directly captured field. This actual Packet Details supports the ICMP row; it does not establish the sender process, user, purpose or authorization.

The current independently executed `decoded-fields.stdout.csv` adds the following to the older all-frames transcript. DNS frames 1/2, 3/4 and 5/6 have IDs 0x044d, 0x044e and 0x044f respectively. Odd frames are queries (`dns.flags.response=False`), even frames are responses (`True`). Names are portal.academy.test, help.academy.test and status.academy.test; each question type is A (1), and each response supplies 198.51.100.80. Directions are 192.0.2.10 → 192.0.2.53 for queries and the reverse for replies. Those are checked decoded fields, distinct from authored inputs.

TCP frames 7–9 have flags 0x0002 SYN, 0x0012 SYN/ACK and 0x0010 ACK, raw seq/ack 1000/0, 9000/1001 and 1001/9001. All have tcp.len=0 and empty tcp.payload. Stream 0 joins 192.0.2.10:54000 and 198.51.100.80:80; GUI relative sequence numbers may differ. No HTTP request, response, exported object, file content or application identity is established by port 80 or this handshake. The original all-frames HTTP fields are all empty.

ICMP frames 10 and 11 decode to types 8 and 0, identifier 300 and sequence 1, in opposite directions. The actual frame 10 GUI details and current decoder agree. The explicitly enabled checksum run reports status 1 (Good) for each IPv4 header, applicable TCP checksum and applicable UDP checksum. Blank cells are inapplicable. The native frame 10 view separately shows its ICMP checksum Good. This is bounded recorded dissection, not a claim every possible property or capture coverage was audited. `_ws.malformed` produced no matching frames in its original run; that alone was never a checksum audit. TShark's root warning is execution context, not packet evidence; learners should run as ordinary users.

## Worked observation, hypothesis, test and assessment

Observation: In this hash-bound workstation-side fixture, the unfiltered native hierarchy has ICMP 2 Packets, 18.2 Percent Packets, 60 protocol Bytes, 2 End Packets and 2 PDUs. The authored CSV describes a workstation and a network device, with a plausible ICMP response but undocumented workstation initiation. Hypothesis: initiation might need an explanation in this observation window; rarity itself is not evidence of hostility. Routine troubleshooting, monitoring, network-device behavior or incorrect dissection remain alternatives.

The `icmp` filter matched frames 10 and 11. Actual frame 10 Packet Details showed an Echo request to the documented network-device address, consistent with the summary label. Current decoder frame 11 is its Echo reply. Packet checking resolves the decoded-protocol question, not ownership or purpose. The filtered hierarchy measured those two packets; reopening after clearing the filter restored the broader 11 loaded frames. A display filter does not alter the PCAP, recover missed collection, or restore packets excluded by a read filter.

Assessment: inconclusive regarding authorization and purpose. Ask the asset owner whether diagnostics or monitoring were expected, and verify collection point, time window and missing telemetry. A single workstation capture on a switched network does not include all unrelated unicast traffic; absence here is not network-wide absence. Preserve the observed mix, exact named measures, filters and frame references for another analyst. The next lesson may pivot through Endpoints and Conversations without inferring users or intent. If no usable packet match exists on a learner's separate capture, leave packet evidence unresolved rather than borrowing this key.

The lecture mentions no required HTTP/object/file exercise and no supplied original case. If a separate DNS-baseline or application-content assignment is given, preserve and assess its own resource; this zero-payload TCP handshake cannot satisfy that separate task. Optional Windows commands in setup are not claimed executed. All historical manifests remain dated snapshots; use the separate current inventory for delivered bytes.
