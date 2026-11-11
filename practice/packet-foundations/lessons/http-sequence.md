# Read HTTP Requests and Responses as a Sequence

**Supplemental synthetic practice.** This is not the unavailable case mentioned in the saved lecture. Use only [the supplied tcp-http-download.pcap](../captures/tcp-http-download.pcap) and the declared synthetic specification. No live collection is needed.

## File and collection context

Filename: `tcp-http-download.pcap`. This is a complete authored offline fixture, generated from the matching JSON specification; it has no physical collection point or real organization. The fictional observation point sees the listed Ethernet/IPv4 exchanges only. It cannot establish what happened outside this file. The first/last packet timestamps are 2025-01-16T12:00:00.000+00:00 and 2025-01-16T12:00:00.300+00:00 (UTC).

Before analysis, calculate SHA-256 of the downloaded file using `Get-FileHash -Algorithm SHA256` in PowerShell or `sha256sum` on Linux, supplying this file's path. SHA-256 is a byte-integrity fingerprint, not proof of provenance or a real incident. Compare it with `509e1644ee06cdecac679a07aa0384041ba0105efb03cd9270ba75682a48824d` and the linked verification receipt; retain the filename and digest in your notes. Record the actual displayed time zone. Compare absolute times only after accounting for that zone; elapsed differences are independent of the displayed zone.

## Learner worksheet

1. Apply `http.request || http.response` to locate HTTP frames; record this filter. Link the request and response using the same TCP endpoint/port exchange and packet time order. Locate the HTTP request and the response linked to it. Record frame numbers, method, path, Host and response code.
2. Distinguish the Host header, prior DNS A answer and actual packet endpoints.
3. Record Content-Type and the response body byte length. What is actually visible in this plain-text fixture?
4. Why would these observations not reveal an HTTPS session body, establish malicious purpose or prove that a user opened the object?

| Observation and exact frame reference | Tentative explanation | Alternative or unknown | Evidence limit / next authorized record |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

Record display-filter state: __________

Record display time zone and source file hash: __________

Bounded conclusion: __________

## Answer key — read after completing the worksheet

Frame 6 contains GET /sample/notes.txt with Host files.academy.test. Frame 8 contains the decoded 200 response, Content-Type text/plain and a 72-byte inert body. Clear the HTTP filter before checking DNS: frame 2 is the earlier DNS answer that maps the synthetic name to 198.51.100.20, and the TCP packets actually use that address. Those are separate observations, not identity or trust assertions. This is authored unencrypted HTTP, not evidence of decrypted HTTPS. The packet exchange does not prove user interaction, file execution, legitimate purpose or compromise.

The checks refer to the exact downloadable fixture, independently decoded with TShark. See [its verification receipt](../verification/tcp-http-download.json). These facts must not be presented as an observed result of the saved lecture's missing case.
