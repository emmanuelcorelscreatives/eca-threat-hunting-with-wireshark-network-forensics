# Answer guide — separate synthetic Academy exercise

The historical capture discussed in the unchanged lecture was not supplied. This guide answers only the supplemental, authored `practice.pcap`; it does not supply historical case findings or a completed learner-owned investigation. The fixture's client-facing capture point is scenario metadata, not proof about a real sensor. Its source identity is SHA-256 `de49b4bc93e17959c8bfad00ad38b580e358d0e8f4adb8c5c90e375b413b72a0`. The synthetic scope in `scope-card.md` is client `192.0.2.10` to peer `198.51.100.20`, TCP destination port `80`, during 2025-01-16 12:00:00.000000–12:02:00.140000 UTC.

**What was checked:** `capture-info.stdout.txt` reports 26 Ethernet packets, 1,542 captured-frame bytes, a 1,982-byte file, microsecond PCAP timestamp precision and a 120.140000-second span. `all-frames.stdout.txt` supplies original frames, UTC and epoch times, tuples, streams, raw TCP numbers, lengths, payload and HTTP decode; it does **not** export TCP flags or checksum status. The separately executed `decoded-fields.stdout.csv` exports flags, a retransmission indication for frame 4 and IP/TCP checksum-status fields. More decisively, the read-only `check_capture.py` parsed the PCAP bytes independently of the builder and compared them with `executed-fixture-spec.json`. Its retained `independent-pcap-report.json` validates record count, order and times, flags, IP and TCP checksums, raw sequence and ACK checks, the same-tuple SYN retry, scoped interval arithmetic and captured HTTP byte origins. `independent-pcap-execution.json` records the successful execution: its recorded argv names the private checker source, while the supplied `check_capture.py` has the same recorded SHA-256. Do not represent a command naming the copied file as the literal recorded argv. The four corrupted *scratch-copy* rejection tests in `independent-checker-rejection-proof.json` did not change the source.

The report's `verdict: pass` applies to those **file-byte checks**, not to authorization, complete collection, an accurate capture clock or all possible ACK history. In particular, frame 1's raw ACK `14001` is classified `not_established_by_prior_observed_bytes`: no preceding reverse-direction sequence end is in this capture. Later ACKs matching observed ends do not resolve what happened before capture began. An empty `_ws.malformed` result in `malformed.stdout.txt` is not the independent audit. Raw values below mean `tcp.seq_raw` and `tcp.ack_raw`, not Wireshark's optional relative sequence display.

The *current* `offline-builder.py` exclusively creates its output rather than overwriting an existing file. `builder-safety-and-rebuild-execution.json` records a fresh, matching 1,982-byte rebuild and both same-output and different-existing-output refusals. `historical-actual-execution-proof.json` is an immutable **older** execution manifest, not a current inventory: it names the former builder hash, older prose and an incorrect empty CSV-header entry. Its older rebuild entry does not establish an exact argv. `source-copy-provenance.json` documents its retained identity. Do not turn proposed student commands or copied filenames into claims of historical execution.

## Series A: scoped TCP connection attempts

**Rule:** retain the first observed client SYN without ACK for each *separate* scoped attempt; exclude a retry. The verified SYN-without-ACK candidates in the full capture are frames 3, 4, 18, 19, 20 and 24. Narrowing to the scoped client, peer and destination port leaves 3, 4, 20 and 24. Frame 4 is the same directional four-tuple, source port `54000`, raw SYN sequence `1000` and stream `1` as frame 3, 0.400000 seconds later. The raw-byte report identifies it as a retry candidate, `decoded-fields.stdout.csv` marks retransmission, and the scoped native view listed in `native-independent-approvals.json` visibly marks it TCP Retransmission. It is **not** another start.

| Accepted original frame | `tcp.stream` | Client port; raw SYN sequence | UTC start | `frame.time_epoch` | Previous accepted frame | Interval |
| --- | ---: | --- | --- | ---: | ---: | ---: |
| 3 | 1 | 54000; 1000 | 12:00:00.100000 | 1737028800.100000000 | — | — |
| 20 | 4 | 54001; 2000 | 12:01:00.100000 | 1737028860.100000000 | 3 | 60.000000 s |
| 24 | 5 | 54002; 3000 | 12:02:00.100000 | 1737028920.100000000 | 20 | 60.000000 s |

The subtractions are `1737028860.100000000 − 1737028800.100000000 = 60.000000000` seconds and `1737028920.100000000 − 1737028860.100000000 = 60.000000000` seconds. The first accepted event has **no prior accepted interval**, even though Wireshark can show `0.000000` in the first displayed row. Frames 5–6, 21–22 and 25–26 are handshake follow-up; a handshake alone establishes neither an application request nor an initiating process.

## Series B: visible HTTP request starts, not connections

**Rule:** use the first **observed request bytes** sent toward the scoped peer, consistently. Both requests use stream `1`, so they are not two new TCP connections. The `http.request` decode appears on frames **8** and **12**; inspect the segments before assigning first-byte times. The actual scoped decode and expanded frame-7, frame-8 and frame-12 views are identified in `native-independent-approvals.json`. The separate raw-byte reconstruction in `independent-pcap-report.json` agrees with them.

| Accepted first-byte frame | `tcp.stream` | Captured request evidence; `tcp.len` | UTC first bytes | `frame.time_epoch` | Previous accepted frame | Interval |
| --- | ---: | --- | --- | ---: | ---: | ---: |
| 7 | 1 | `GET /a HTTP/1.1\r\n`; 17 TCP bytes | 12:00:01.100000 | 1737028801.100000000 | — | — |
| 12 | 1 | `GET /b HTTP/1.1\r\nHost: fixture.example\r\n\r\n`; 42 TCP bytes | 12:00:21.100000 | 1737028821.100000000 | 7 | 20.000000 s |

Frame 7 starts with payload hex `474554202f6120485454502f312e310d0a` and raw sequence `1001`. Frame 8 supplies `Host: fixture.example\r\n\r\n`, 25 more bytes starting at raw sequence **1018 = 1001 + 17**. Frame 9 ACKs **1043 = 1018 + 25**. The `/a` header completes and is decoded on frame 8, but its first captured bytes are in frame 7. Frame 12 both begins and completes the 42-byte `/b` request at raw sequence **1043**; frame 13 ACKs **1085 = 1043 + 42**. The captured handshake and byte origins support this rule **in this fixture**; they cannot reveal an absent first portion in another capture.

The request-start subtraction is `1737028821.100000000 − 1737028801.100000000 = 20.000000000` seconds. By contrast, the decoded `http.request` rows 8 (`1737028801.120000000`) and 12 (`1737028821.100000000`) are **19.980000000** seconds apart. That is arithmetic between *decode rows*, not this worksheet's first-byte interval. The accepted-only request display must show frames **7 and 12**, not merely `http.request`. Native approved epoch and previous-displayed-row views show `1737028801.100000`, `1737028821.100000`, then `0.000000`, `20.000000` for those accepted-only frames; the first displayed `0.000000` is not a first-event worksheet gap.

For frames 7, 8 and 12, `frame.len` and `frame.cap_len` are respectively **71/71**, **79/79** and **96/96** bytes; `tcp.len` is **17**, **25** and **42** bytes. Frame lengths include Ethernet, IP and TCP headers. Neither measure is the size of an HTTP file body or of the 1,982-byte PCAP. `http.file_data` in `all-frames.stdout.txt` supplies no request body. The `204` response codes occur on frames 10 and 13, not on request starts. Wireshark Capture File Properties in the approved native view shows a **1,966-byte Length** counter rather than filesystem size; `native-file-accounting.json` reconciles the 16-byte difference without suggesting truncation.

## Decisions covering all 26 original frames

The stream and packet fields below come from `all-frames.stdout.txt`, with flags cross-checked in `decoded-fields.stdout.csv` and `independent-pcap-report.json`. `tcp-conversations.stdout.txt` lists the six tuples. Retain excluded and uncertain candidates rather than making the sequence appear regular.

| Original frame(s) | Stream | Worksheet decision and reason |
| --- | ---: | --- |
| 1–2 | 0 | Scoped ACK-only traffic at the capture boundary. No SYN is observed; the connection start and frame 1's prior ACK coverage remain **uncertain**. Do not use frame 1 as a fabricated start. No request is decoded. |
| 3 | 1 | **Accept** first scoped connection-attempt start. |
| 4 | 1 | **Exclude** same-tuple, same-raw-SYN-sequence retry of frame 3. |
| 5–6 | 1 | **Exclude** reverse SYN/ACK and client ACK; neither is another client start. |
| 7 | 1 | **Accept in request series only:** first observed `/a` bytes; not a new connection. |
| 8 | 1 | **Exclude as another start:** continuation and decoded `/a` row, not the first-byte frame. |
| 9–11 | 1 | **Exclude** ACK, frame-10 `204` response and subsequent ACK. |
| 12 | 1 | **Accept in request series only:** first bytes and decoded `/b` on the existing connection. |
| 13–17 | 1 | **Exclude** frame-13 `204` response, ACKs and frame-15/16 FIN/ACK closing traffic. Do not call closing packets keep-alives. |
| 18 | 2 | **Exclude** SYN from `192.0.2.11`, not the scoped client. |
| 19 | 3 | **Exclude** SYN to `203.0.113.20`, not the scoped peer. |
| 20 | 4 | **Accept** next scoped connection-attempt start. |
| 21–23 | 4 | **Exclude** handshake follow-up and later ACK-only frame 23. It is not a new start or decoded request; a keep-alive mechanism is not established. |
| 24 | 5 | **Accept** third scoped connection-attempt start. |
| 25–26 | 5 | **Exclude** handshake follow-up; no request is decoded on this stream. |

`ip-conversations.stdout.txt` counts 24 frames for the scoped address pair and one for each distractor pair: packets in the same pair are not automatically separate contacts. `protocol-hierarchy.stdout.txt` counts 26 TCP frames, four HTTP-decoded frames and one `tcp.segments` frame, consistent with the split request; it supplies no DNS finding. The HTTP Host field does not establish DNS resolution or a NAT mapping.

**Interpretation and limits:** the short authored window supports three comparable scoped connection attempts and **two** observed 60-second gaps, plus two comparable first-byte request starts and **one** observed 20-second gap. These are different event types, not conflicting calculations. Two equal connection gaps do not establish a durable periodic process; one request gap cannot establish request periodicity. Stream 0's missing connection start remains unresolved. The fixture does not establish loss-free or bidirectional coverage outside what is shown, clock calibration, endpoint process, service purpose, remote instructions or command and control. Scheduled software is an ordinary alternative. A real authorized capture with too few confirmed comparable starts must report timing **unresolved**, and may require separately authorized endpoint, service, capture-health and clock evidence. The next lesson addresses jitter, gaps and long-lived sessions.

**Current review boundary:** approved native PNGs establish only their recorded Linux states. The four new `native-gap-*` views demonstrate that out-of-filter reference frame 10 remains between accepted starts and changes frame 20's displayed predecessor gap to 58.940000 seconds; unsetting it restores rows 3, 20 and 24 and the two 60-second accepted gaps. See `native-validation.md` for exact files and menu state. The setup and worksheet distinguish these completed author-provided GUI observations from the separate checks each learner must carry out. A separate complete current-kit content review, repository publication and main visual/render approval remain distinct requirements. Windows behavior and a learner's own capture are not claimed.
