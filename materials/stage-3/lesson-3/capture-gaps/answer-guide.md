# Answer guide — actual decoded results

The files are synthetic practice, not evidence from the unavailable narrated incident. All-view CLI execution and deterministic regeneration are recorded in actual-execution.json; complete/truncated/one-sided prefixed logs are current. No malformed matches were reported for any view.

| View | Saved frame count | Bounds UTC on 2025-02-03 | Directions | Clipped matches |
|---|---:|---|---|---|
| Complete | 11 | 12:00:00.000–12:00:00.100 | A→B and B→A | none |
| Truncated | 11 | 12:00:00.000–12:00:00.100 | A→B and B→A | frame 6: 54 saved / 64 original bytes |
| One-sided | 6 | 12:00:00.000–12:00:00.090 | A→B only | none |

A is 192.0.2.10:40000; B is 198.51.100.20:8080. Complete/truncated frame 4 carries 13 captured bytes `QUERY:STATUS` plus newline. Complete frame 6 carries 10 captured bytes `STATUS:OK` plus newline; truncated frame 6 has the same original TCP length but no saved payload bytes. The truncated file alone cannot disclose that reply text. In the one-sided view the request is frame 3; no reply is visible. That does not prove B sent no reply.

Raw sequence/ACK progression is in each *-fields.stdout.txt: request seq 1001, reply ACK 1014, reply seq 9001, following A ACK 9011; FIN increments reach ACK 9012/1015 in the complete view. Relative GUI sequence numbers are distinct from these raw fields. One-sided ACK progression references unseen B sequence space but proves neither missing content nor why B records are absent. Port 8080 may trigger HTTP dissection; the arbitrary fictional text is not valid HTTP solely because a dissector labels it.

TCP checksum status 2 is unverified in the recorded default decode. It is not a bad-checksum conclusion. Classic PCAP lacks collection drop telemetry and measured capture-point provenance here: record dropped packets as not available. The header's 65535 snapshot length does not establish a real collector configuration. Native Properties displays Unknown dropped packets, 11 packets and 0.100 s. This Linux4.4 reader reports 791 bytes for the actual 807-byte truncated file, a 16-byte file-accounting difference; its 617 packet bytes are a third measure. Do not replace filesystem size or hashes with the GUI length. Top time labels round; use decoded epoch fields or the statistics time span for fractional boundaries.

| File | SHA-256 |
|---|---|
| captures/session-complete.pcap | a8c6fafb05030cd57de4523def2de01a4f585b64383bc2fd7bc6f326422f7933 |
| captures/session-truncated.pcap | 8788a107756ba024709be5b2b4942ca7ed50793f06c3057cccf7782ae00775fd |
| captures/session-one-sided.pcap | 8025574cd396d1d2a1149ad42d8cc2d1c5eddbf6812eb446110a53faf2d23b37 |

Request acquisition settings or a capture with needed bytes for clipping; collector telemetry for possible drops; authorized return-path or second-vantage evidence for missing direction. Keep unknown causes inconclusive. For later clock comparison retain source clock/timezone/precision and uncertainty; the next lesson covers making times comparable.
