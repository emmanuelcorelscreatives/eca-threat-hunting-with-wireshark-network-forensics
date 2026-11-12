# Answer key — validated fixture and bounded reasoning

This packet key supersedes the old design-only answer-guide.md. It is for the Academy synthetic fixture, not a historical incident. The original CSVs retain DESIGN labels. The fixture has both directions by offline construction; there is no real collection point or evidence independently mapping a real WKST-01. Dates, durations, addresses and inventory are authored.

Actual Linux TShark output: 76 frames, 13,228 Ethernet-frame bytes, four TCP conversations, and 15,840 total PCAPNG bytes. Each stream has 19 frames and 3,307 frame bytes. Asset-to-peer: 10 frames / 904 bytes; peer-to-asset: 9 frames / 2,403 bytes. Bytes include Ethernet headers, not PCAPNG container overhead. See conversations.txt and decoded-fields.csv.

| Stream | Four-tuple | First–last frame | Frames / bytes | Asset→peer ; peer→asset | SYN/SYN-ACK | Hello frames | FIN frames |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 192.0.2.10:54001 → 198.51.100.20:443 | 1–76 (interleaved) | 19 / 3307 | 10/904 ; 9/2403 | 1,2 | 4,6 | 73,75 |
| 1 | 192.0.2.10:54101 → 203.0.113.40:443 | 16–34 (interleaved) | 19 / 3307 | 10/904 ; 9/2403 | 16,17 | 19,21 | 31,33 |
| 2 | 192.0.2.10:54102 → 203.0.113.40:443 | 35–53 (interleaved) | 19 / 3307 | 10/904 ; 9/2403 | 35,36 | 38,40 | 50,52 |
| 3 | 192.0.2.10:54103 → 203.0.113.40:443 | 54–72 (interleaved) | 19 / 3307 | 10/904 ; 9/2403 | 54,55 | 57,59 | 69,71 |

Stream 0 starts 12:01:00 UTC and ends 12:12:00 (660 seconds). Stream 1 starts 12:04:00, ends 12:04:06 (6 seconds). Stream 2 starts 12:07:00, ends 12:07:07 (7 seconds). Stream 3 starts 12:10:00, ends 12:10:09 (9 seconds). Each first three packets form its TCP setup; close is FIN, ACK, FIN, ACK. TCP sequence/acknowledgment and checksums were checked by the independent local checker; no malformed, missing-segment or retransmission frames were returned by the supplied actual TShark checks. This does not prove real network fidelity beyond the deliberately simple fixture.

At 1-second resolution each stream's opening exchange occupies its start second, followed by quiet time and four closing packets near the end. At 180-second resolution a graph can combine a close and a later setup in one time bin. A graph peak is not a new-session finding: inspect the SYNs and distinct TCP stream IDs. Stream 0 is long because of its synthetic idle interval, not continuous application activity. Bin output includes any endpoint boundary behavior; consult exact graph-1s.txt and graph-180s.txt rather than inventing heights. Traffic-size equality is by authored design and says nothing about benignness or request count.

ClientHello and ServerHello are visible in each stream with supported version 0x0304 (TLS1.3). The exact hello frames are in the table and tls-handshakes.txt. No SNI was supplied when generating the TLS exchanges; no DNS or QUIC packets were authored. name-visibility.txt is empty. TLS1.3 protects later handshake/application contents; no certificate or request hostname should be inferred from these outputs. There is no ECH demonstration or claimed ECH acceptance, no encrypted-DNS proof and no proxy traversal evidence. In a real capture, missing DNS has multiple explanations, including caching, missed collection, direct-IP use and encrypted resolution.

ECH reasoning: a public outer ClientHello name may differ from the intended protected backend; an offer alone cannot establish acceptance, rejection or retry. QUIC reasoning: an observable Initial does not reveal the later final protected request. Decryption requires separate authorization, matching secrets and sufficient packets; this lab supplies no secrets and asks for no decryption.

A harmless alternative for repeated short sessions is scheduled maintenance, retries or routine polling. Seek authorized baseline and operational context. The service inventory label remains hypothetical and cannot establish that a connection is an approved update. Neither address, timing nor size identifies process, website, protected payload or purpose.

Example bounded claim: “In the authored fixture, 192.0.2.10:54101 initiated TCP stream 1 to 203.0.113.40:443; the SYN/hello and opposite-direction response support bidirectional contact from 12:04:00 to 12:04:06 UTC. Host identity, initiating process, requested name and purpose remain unknown from this file.” Confidence can be high in this fixture's decoded contact, but not in its correspondence to a real host or event.

Example smallest request: “For the independently mapped asset and 203.0.113.40, 2025-01-16 12:03:30–12:10:30 UTC, provide retained process and connection events, explain connection-to-process linkage and clock basis, identify any retained name fields and missing records. If confirmed proxy traversal applies, provide the matching transactions and only hostname/request fields actually seen and retained.” The window is an exercise design choice encompassing the three short flows; tighten it using the real case's verified timestamps and mapping. Do not presume endpoint or proxy records exist.

Award credit for exact packet references and units, matched graph rules, a harmless alternative, explicit claim-specific uncertainty and a targeted conditional request. Do not award credit for guessed names or claims that this is the lecture's absent case or completed learner homework. Transition to Stage 15 by stating the observable contact claim and the missing field that could change its interpretation.
