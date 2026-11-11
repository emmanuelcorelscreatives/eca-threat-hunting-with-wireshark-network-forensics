# Investigate UDP and ICMP Conversations

**Supplemental synthetic practice.** This is not the unavailable case mentioned in the saved lecture. Use only [the supplied udp-icmp.pcap](../captures/udp-icmp.pcap) and the declared synthetic specification. No live collection is needed.

## File and collection context

Filename: `udp-icmp.pcap`. This is a complete authored offline fixture, generated from the matching JSON specification; it has no physical collection point or real organization. The fictional observation point sees the listed Ethernet/IPv4 exchanges only. It cannot establish what happened outside this file. The first/last packet timestamps are 2025-01-16T12:00:00.000+00:00 and 2025-01-16T12:00:03.020+00:00 (UTC).

Before analysis, calculate SHA-256 of the downloaded file using `Get-FileHash -Algorithm SHA256` in PowerShell or `sha256sum` on Linux, supplying this file's path. SHA-256 is a byte-integrity fingerprint, not proof of provenance or a real incident. Compare it with `d728f6a6066aa9dd3220903dc865269a2715862f4dd95e84dcdc8f164d59460e` and the linked verification receipt; retain the filename and digest in your notes. Record the actual displayed time zone. Compare absolute times only after accounting for that zone; elapsed differences are independent of the displayed zone.

## Learner worksheet

1. Use Statistics → Conversations, UDP, and record any display-filter restriction; inspect both packet directions with `udp`. Identify the UDP endpoint/port pair and record examples in both directions. Are the payload words ACK transport acknowledgments?
2. Clear the UDP filter, then inspect `icmp`. Check for ICMP errors quoting a UDP packet; if none appears, report only that none is present in this file. Echo is not an ICMP error. Locate the ICMP echo request and reply. Record type, identifier, sequence and displayed time difference.
3. Describe the repetition without naming a real application or malicious beacon.
4. Explain which outcome, purpose, host and collection-context claims remain unsupported.

| Observation and exact frame reference | Tentative explanation | Alternative or unknown | Evidence limit / next authorized record |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

Record display-filter state: __________

Record display time zone and source file hash: __________

Bounded conclusion: __________

## Answer key — read after completing the worksheet

Frames 1–6 are three authored UDP message/reply pairs, between 192.0.2.10:55000 and 198.51.100.20:9999. The pairs are frames 1/2, 3/4 and 5/6: odd frames travel from 192.0.2.10:55000 to 198.51.100.20:9999; even frames return. Payload strings containing ACK are authored application data, not UDP transport acknowledgments or independent proof that a real application received or processed data. Frames 7/8 are ICMP types 8/0, identifier 7, sequence 1, separated by 0.020 seconds. No ICMP error or quoted UDP packet occurs in this file. The echo exchange must not be used as evidence of a UDP error relationship. Timing and repetition were designed. Port 9999 and text do not identify a real application, malicious beacon, person or permission. Echo pairing does not establish broader host health, environmental visibility or compromise.

The checks refer to the exact downloadable fixture, independently decoded with TShark. See [its verification receipt](../verification/udp-icmp.json). These facts must not be presented as an observed result of the saved lecture's missing case.
