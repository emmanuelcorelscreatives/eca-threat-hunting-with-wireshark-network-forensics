# Synthetic input schema and evidence limits

Every `specs/*.json` has `version:1`, `synthetic:true`, a `fixtureId`, purpose, explicit synthetic observation-point description, matching saved lesson project IDs, and ordered `events`. An event is a designed packet, not a collector log or observed host action.

| Field | Meaning |
|---|---|
| `timestamp` | Fixed ISO8601 timestamp with an explicit UTC offset; the PCAP preserves microsecond precision. |
| `kind` | Supported generator type: DNS A query/answer, raw TCP, raw UDP, ICMP echo/request or reply. |
| `src`, `dst` | Documentation-only IPv4 packet endpoints; not people, accounts or real hosts. |
| `sport`, `dport` | Transport port integers. A port alone does not prove an application or purpose. |
| `name`, `transactionId`, `answer` | Authored DNS question, transaction identifier and A-record answer. An answer address is not proof of a later connection to it. |
| `flags`, `seq`, `ack` | Raw TCP flag letters, sequence and acknowledgment numbers. |
| `payloadText` / `payloadBase64` | Authored inert payload bytes; exactly one encoding may be supplied. |
| `identifier`, `sequence` | ICMP echo pairing fields. |
| `capturedBytes` | Optional intentional truncation length; none of these three supplied fixtures uses truncation. |

All MAC addresses are locally administered synthetic values. PCAP link type is Ethernet; IPv4 and transport checksums are computed. The classic PCAP files do not establish an actual capture interface, driver, drop count, collector, capture authorization or environmental coverage. The synthetic context comes from these teaching specifications, not an invented Capture File Properties field.

Verification JSON fields `actualDecodedFields` are TShark observations of these files. `captureSha256` identifies the exact bytes, `specSha256` identifies the input, and program hashes identify the generator and verifier. `exportedInertHttpObjects` describes only the exported synthetic text. No actual user opening, program execution, sign-in, attacker control or malicious intent is encoded or proven.

The generated fixtures are independent classroom examples. Their IPs, times and packet references must not be attributed to a saved lecture that explicitly has no supplied case file.
