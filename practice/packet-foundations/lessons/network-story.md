# Read the Network Story Before Naming the Attack

**Supplemental synthetic practice.** This is not the unavailable case mentioned in the saved lecture. Use only [the supplied network-story.pcap](../captures/network-story.pcap) and the declared synthetic specification. No live collection is needed.

## File and collection context

Filename: `network-story.pcap`. This is a complete authored offline fixture, generated from the matching JSON specification; it has no physical collection point or real organization. The fictional observation point sees the listed Ethernet/IPv4 exchanges only. It cannot establish what happened outside this file. The first/last packet timestamps are 2025-01-15T23:59:58.000+00:00 and 2025-01-16T00:00:03.050+00:00 (UTC).

Before analysis, calculate SHA-256 of the downloaded file using `Get-FileHash -Algorithm SHA256` in PowerShell or `sha256sum` on Linux, supplying this file's path. SHA-256 is a byte-integrity fingerprint, not proof of provenance or a real incident. Compare it with `5200808c26e38d89cc6fe52549bbf14dfddc178afc787ee85c402b24d2469188` and the linked verification receipt; retain the filename and digest in your notes. Record the actual displayed time zone. Compare absolute times only after accounting for that zone; elapsed differences are independent of the displayed zone.

## Learner worksheet

1. With filters cleared, record the first and last packet references and displayed absolute times with their display time zone, then calculate the elapsed span.
2. Which IPv4 addresses actually send or receive packets? Which address appears only inside DNS answers?
3. Record the decoded protocol layers and one packet in each observed direction. Do not add layer counts as disjoint packet groups.
4. Write a neutral network description, an ordinary possible explanation, an unknown and one next-context question. What cannot be concluded about an attack?

| Observation and exact frame reference | Tentative explanation | Alternative or unknown | Evidence limit / next authorized record |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

Record display-filter state: __________

Record display time zone and source file hash: __________

Bounded conclusion: __________

## Answer key — read after completing the worksheet

The actual file has 6 frames. Frames 1 and 6 span 2025-01-15 23:59:58 UTC through 2025-01-16 00:00:03.050 UTC, a 5.050-second interval. Displayed local clock times can differ. The communicating IP endpoints are 192.0.2.10 and 192.0.2.53. All six frames decode Ethernet/IPv4/UDP/DNS; the repeated layer counts refer to the same frames. Frames 1/2,3/4 and 5/6 are query/response pairs. The returned 198.51.100.20 address occurs in A-record answers; this file contains no packet exchanged with it. An ordinary name lookup is a possible description, not proof of purpose or authorization. The file does not identify a person, process or attack. Ask for authorized asset and collection context, and retain unresolved conclusions.

The checks refer to the exact downloadable fixture, independently decoded with TShark. See [its verification receipt](../verification/network-story.json). These facts must not be presented as an observed result of the saved lecture's missing case.
