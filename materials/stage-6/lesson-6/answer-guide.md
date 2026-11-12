# Answer guide

## Scope and conclusions
Both practice captures are offline synthetic teaching material, not recorded lecture traffic. There is no measured interface, wire direction, collection coverage or measured drop count. Richer timestamps are authored from 2023-11-14 22:13:20 UTC at 0.1-second intervals (first frame at the base time); baseline events span authored 2025-01-16 12:00:00.000–.140 UTC. Manifest direction is authored A to B, not measured direction. Generated files have no collector or collection filter; these facts do not establish real capture completeness.

## Richer capture: exact independently decoded fields
Blank means no value in the supplied decode, not zero or proof of failure. Checksums below use TCP and UDP validation enabled.

|Frame|cap/len|IPv4 ID; offset; MF|IPv6 ID; offset; more|TCP raw seq; len; status|UDP status|
|---|---|---|---|---|---|
|1|58/58|0x0064; 0; True||||
|2|50/50|0x0064; 3; False|||3|
|3|58/58|0x0065; 0; True||||
|4|86/86||0x000000c8; 0; True|||
|5|78/78||0x000000c8; 3; False||1|
|6|102/102||0x000000c9; 0; False||1|
|7|42/74|0x0066; 0; False|||3|
|8|3054/3054|0x012c; 0; False||1000; 3000; 0||
|9|1054/1054|0x012d; 0; False||1000; 1000; 1||
|10|1054/1054|0x012e; 0; False||2000; 1000; 1||
|11|1054/1054|0x012f; 0; False||3000; 1000; 1||

Both reassembly-reference columns (`ip.reassembled_in`, `ipv6.reassembled.in`) were blank for all eleven rows in the supplied decode. Do not substitute invented reference values or conclude that blank references disprove matching fragments.

### Packet-specific interpretations
1. IPv4 first piece: source 192.0.2.10, destination 198.51.100.20, protocol UDP (17), ID 100. IP payload bytes 0–23; MF set.
2. Same identity tuple as frame 1, offset 3 × 8 = 24 bytes, final payload bytes 24–39. Together they cover the 40-byte UDP datagram. IPv4 UDP checksum zero is absent, status **3**, not BAD.
3. Same addresses/protocol but ID 101: separate first piece, bytes 0–23, MF set. Needed final piece is not supplied. Incomplete here does not localize network loss.
4. IPv6 source 2001:db8::10 to 2001:db8::20, Fragment ID 200, offset zero, more set; first 24 bytes of the UDP datagram.
5. Same IPv6 grouping, offset 3 × 8 = 24, more clear; final 16 bytes. Frames 4–5 fit together; reassembled UDP checksum status **1 GOOD**.
6. IPv6 ID 201, zero offset and more clear: atomic Fragment header, whole datagram in one packet, not evidence of missing pieces. UDP status **1 GOOD**. IPv6 fragmentation is performed by the source, not intermediate routers.
7. Saved 42 of 74 reported bytes: 32 bytes absent from this record. Offset zero and MF clear: truncation, not fragmentation. IPv4 UDP zero checksum status **3** means absent checksum.
8. Authored aggregate: 3000 TCP bytes starting at raw sequence 1000, checksum placeholder zero decodes **0 BAD** with validation enabled. This is a synthetic pre-segmentation illustration, not a measured partial checksum or actual hardware offload. No IP fragmentation flags/offset evidence.
9. Authored 1000-byte segment covering sequence bytes 1000–1999; computed checksum **1 GOOD**.
10. Authored 1000-byte segment covering 2000–2999; computed checksum **1 GOOD**.
11. Authored 1000-byte segment covering 3000–3999; computed checksum **1 GOOD**. Frames 9–11 conceptually cover the same bytes as frame 8. They are not an independent downstream observation or proof of actual on-wire size/checksum. Combining overlapping conceptual views in one file can affect TCP analysis.

The IPv4 filter matches 1, 2, 3; the IPv6-header filter matches 4, 5, 6; the shortened-record filter matches 7. The supplied `_ws.malformed` query returned no frames; this does not certify complete traffic.

## Baseline: specification and actual native decode
These event descriptions follow fixture-spec.json; baseline-decoded.stdout.txt supplies the independently executed native frame lengths, sequences, fragment flags and offsets. All TCP traffic uses 192.0.2.10:41000 and 198.51.100.20:45000.

|Frame|Authored event|Interpretation|
|---|---|---|
|1|Client SYN, seq 1000, ack 0|Start of authored handshake; no payload|
|2|Server SYN/ACK, seq 7000, ack 1001|Acknowledges client SYN|
|3|Client ACK, seq 1001, ack 7001|Completes authored handshake|
|4|Client PSH/ACK, seq 1001, ack 7001, `FIRST\n`|Six bytes, sequence 1001–1006|
|5|Server ACK, seq 7001, ack 1007|Acknowledges through 1006|
|6|Client PSH/ACK, seq 1014, ack 7001, `TAIL\n`|Five bytes, sequence 1014–1018; seven sequence bytes 1007–1013 absent from saved payload|
|7|Server ACK, seq 7001, ack 1007|Does not advance beyond the gap in this authored example|
|8|UDP 203.0.113.10:42000 → 192.0.2.20:43000|42 captured of 100 reported bytes: 58 missing bytes, including payload|

Baseline TCP frames are 54 bytes without payload, frame 4 is 60, frame 6 is 59; none is IP-fragmented. Frame 8 has a complete UDP header but not the full payload. Its builder computes a nonzero checksum over the full datagram; missing bytes prevent independent full validation from the saved record. Do not equate it with the richer IPv4 zero-checksum cases.

Follow can expose available `FIRST` and `TAIL` content, but exact gap presentation depends on analysis/version. It cannot recover seven missing sequence bytes or certify a complete application exchange. An apparent TCP gap is not an IP fragment gap and does not locate loss. The ACK behavior in generated practice is not independent network evidence.

## Comparison and reasoning rubric
Record actual before/after settings, not assumed defaults. Available names are listed in setup; changes affect dissection only. Invalid checksums may exclude packets from reassembly with validation enabled; report only the effects you actually observe. Some supported versions recognize certain partial TCP/UDP checksums, but this does not convert frame 8's authored placeholder into hardware evidence.

Matching identity fields, offsets and final-piece flags support genuine IP fragmentation in the simulated examples. Neither close timestamps nor ID alone is sufficient. Missing fragments, late start, capture filtering, missed paths and collection loss can yield similar gaps; shortened frames are a distinct clue. A transport-header collection filter may omit later fragments without the relevant header. Display filters cannot restore excluded packets. Missing drop statistics are not zero drops. Expert Information is a lead, not a verdict.

To establish actual offload, obtain authorized, documented sender-side and independent post-interface observations of a comparable exchange, correlate sequence ranges/content/direction/times, and record interface/offload configuration, capture filters, snap length and collector statistics. Account for capture quality and path differences. Without this evidence, report only the observed host-side size/checksum and offload as a possibility. For missing pieces request a fuller documented capture; for truncation request sufficient saved bytes. Preserve originals and leave unresolved causes inconclusive.

### Why the saved combined view shows retransmission annotations
Frame 8 already represents raw TCP sequence bytes 1000–3999. Frames 9, 10 and 11 repeat ranges 1000–1999, 2000–2999 and 3000–3999 within that same authored TCP conversation. The actual native TCP filter screenshot consequently labels frames 9–11 as TCP Retransmission. This is an artifact of combining two overlapping conceptual teaching views in one saved file. It is not evidence of actual network retransmission, network loss or measured hardware offload. Independently collected sender and downstream captures would be separate observations with their own documented capture boundaries.
