# What a Packet Can and Cannot Prove

**Supplemental synthetic practice.** This is not the unavailable case mentioned in the saved lecture. Use only [the supplied tcp-http-download.pcap](../captures/tcp-http-download.pcap) and the declared synthetic specification. No live collection is needed.

## File and collection context

Filename: `tcp-http-download.pcap`. This is a complete authored offline fixture, generated from the matching JSON specification; it has no physical collection point or real organization. The fictional observation point sees the listed Ethernet/IPv4 exchanges only. It cannot establish what happened outside this file. The first/last packet timestamps are 2025-01-16T12:00:00.000+00:00 and 2025-01-16T12:00:00.300+00:00 (UTC).

Before analysis, calculate SHA-256 of the downloaded file using `Get-FileHash -Algorithm SHA256` in PowerShell or `sha256sum` on Linux, supplying this file's path. SHA-256 is a byte-integrity fingerprint, not proof of provenance or a real incident. Compare it with `509e1644ee06cdecac679a07aa0384041ba0105efb03cd9270ba75682a48824d` and the linked verification receipt; retain the filename and digest in your notes. Record the actual displayed time zone. Compare absolute times only after accounting for that zone; elapsed differences are independent of the displayed zone.

## Learner worksheet

1. Separate the DNS exchange, TCP setup, HTTP request, HTTP response and close using frame references.
2. What exact visible object bytes can be corroborated? What claim about a user opening or executing them remains unsupported?
3. Record one network observation, one tentative explanation, one alternative, one limitation and the next purpose-specific host record you would request.
4. Could this authored fixture establish a real person, authorization, environmental completeness or compromise? Explain.

| Observation and exact frame reference | Tentative explanation | Alternative or unknown | Evidence limit / next authorized record |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

Record display-filter state: __________

Record display time zone and source file hash: __________

Bounded conclusion: __________

## Answer key — read after completing the worksheet

Frames 1/2 are DNS. TCP setup is 3/4/5; GET is 6; the decoded 200 response is 8; orderly close is frames 10–13. The response body exports as notes.txt with 72 bytes, SHA-256 7c61fe5f1575a719c04bd75fc5787521860e69b7ecb3f4676cc3237dc5574d0b. It is inert authored text. To inspect these bytes, export the HTTP object using Wireshark's HTTP object export, save `notes.txt` in a new exercise folder and view it as plain text. The exact ASCII body is two lines, each terminated by LF, including a final LF:

```text
Emmanuel Corels Academy synthetic teaching text.
No executable content.
```

Compare the exported file's byte length and SHA-256 with the values above. For a claim that a person opened or executed an object, request authorized time-matched endpoint file-access or process-execution records and process-to-connection attribution, rather than inferring this from the GET. This validates a visible network transfer in the fixture, not a person opening it or host execution. A browser request, automated client or another explanation would need authorized host/context records to distinguish. No real incident, person, legitimate purpose or complete environmental coverage follows from this classroom file.

The checks refer to the exact downloadable fixture, independently decoded with TShark. See [its verification receipt](../verification/tcp-http-download.json). These facts must not be presented as an observed result of the saved lecture's missing case.
