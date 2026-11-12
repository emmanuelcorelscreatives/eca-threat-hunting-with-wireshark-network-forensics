# Instructor key — measured selections and evidence limits

This key applies only to the synthetic `practice.pcap` with SHA-256 `55faee8257fa47860f905c5b5f59d37dd04eb75cbf60f7ce0150dd6162b8db23`. All 14 listed filters and the composite were accepted on Linux and Windows TShark 4.4.0; exact ordered frame selections agreed and the Windows filter/open/clear screenshots passed independent review. Use `measured-filter-results.json` and its exact per-command stdout/stderr references. Direct repeated ports and SYN values are exported in `linux-command-16.stdout.txt`. Native copied packet details are supplied separately; copied text is not a claim that every line fits in one screenshot.

## Packet references

`all-frames.stdout.txt` has `http.request.method`/`http.request.uri` on **frame 6** (`GET`, `/reports/report.csv?rev=1`), **frame 11** (`POST`, `/status/reporting.txt`) and **frame 16** (`GET`, `/public/manual.pdf`); these are also the only `frame.protocols` rows ending in `http`. Its `dns.qry.name` shows `training.academy.test` in frames 1–2, and its `dns.a` shows the authored answer `198.51.100.80` in frame 2. Its `tcp.srcport`/`tcp.dstport` show port 80 and 51001–51003 across frames 3–17, and 52001/443, 443/52001, 52001/443 in frames 18–20. `tcp.stream` identifies streams 0–3 for these four exchanges; `tcp-conversations.stdout.txt` independently reports 5, 5, 5 and 3 frames. The authored manifest's event order maps to those frame numbers in this particular one-frame-per-event rebuild, but its blank `observed_frame` cells are **not** a packet-derived manifest and must not be silently filled or presented as student GUI observations.


## Measured filter selections

| Exact expression | Measured source frames on both decoders | Meaning and limit |
|---|---|---|
| `http.request.method` | 6, 11, 16 | Field presence selects the three decoded HTTP requests. |
| `http.request.method == "GET"` | 6, 16 | Equality still retains the benign PDF GET control. |
| `http.request.method!= "GET"` | 11 | The other decoded method is POST; missing method fields do not satisfy this comparison. |
| `!(http.request.method == "GET")` | 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20 | Whole-test negation also retains packets missing the method. |
| `http.request.uri contains "report"` | 6, 11 | The incidental reporting substring also matches; this is not a relevance detector. |
| `http.request.uri matches r"\.(csv\|pdf)(\?.*)?$"` | 6, 16 | The CSV query suffix and PDF extension both match the actual PCRE2 expression. |
| `tcp.port` | 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 | TCP fields exist on TCP frames and not the two DNS/UDP frames. |
| `tcp.port == 443` | 18, 19, 20 | Either occurrence can satisfy equality. |
| `tcp.port!= 443` | 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 | Every present TCP port must differ; this is not the complement of equality over packets missing the field. |
| `!(tcp.port == 443)` | 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 | Negation includes DNS packets lacking tcp.port. |
| `count(tcp.port) == 2` | 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 | Count is repeated-field occurrences in one frame, not unique ports or conversations. |
| `all tcp.port!= 443` | 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 | Explicit every-occurrence inequality gives the recorded selection. |
| `tcp.flags.syn` | 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 | Presence includes a decoded SYN subfield whose value can be zero. |
| `tcp.flags.syn == 1` | 3, 4, 8, 9, 13, 14, 18, 19 | Value 1 selects the actual SYN/SYN-ACK packets. |

The measured composite `http.request.method == "GET" && http.request.uri contains "report"` selects frame **6** and excludes the teaching controls **11 and 16**. It meets this authored inclusion/exclusion objective, not a general incident-detection claim. GET alone and the extension regex both include the benign PDF control. Missing decoding, non-GET traffic and unrelated report-like strings remain reasons that a text match or green filter cannot prove relevance.

## Packet, transport and case limits

The executed `all-frames.stdout.txt` gives `frame.len` **125, 122, 118** and `tcp.len` **71, 68, 64** for request frames 6, 11 and 16 respectively. `tcp.payload` is request text in hexadecimal, **not downloaded CSV/PDF content**; `http.file_data` and `http.response.code` are empty in the export. Raw TCP values (`tcp.seq_raw`, `tcp.ack_raw`, `tcp.len`) show frame 6 sequence **1001** plus **71** request bytes followed by frame 7 ACK **1072**; frame 11 sequence **2001** plus **68** followed by frame 12 ACK **2069**; and frame 16 sequence **3001** plus **64** followed by frame 17 ACK **3065**. These are raw wire sequence values, not necessarily a GUI's relative sequence display. ACKs acknowledge request bytes; they are not HTTP responses. `frame.len` includes the frame, `tcp.len` counts TCP payload, `capture-info.stdout.txt`'s 1,697 bytes is the PCAP file size, and none measures a downloaded file.

On frames 18–20, the logged `tcp.srcport`, `tcp.dstport`, `tcp.seq_raw`, `tcp.ack_raw` and zero `tcp.len` are consistent with the authored port-443 three-way TCP handshake. `frame.protocols` and `protocol-hierarchy.stdout.txt` report no TLS in this file. **Do not promote that handshake into a TLS session, decrypted application exchange, file transfer or malicious finding.** The empty `malformed.stdout.txt` is only an empty result for the executed `_ws.malformed` query; the supplied current field export does not contain checksum-status fields. A previous review's checksum description is not a substitute for recording a fresh check if checksum validation is mandatory. The absence of response fields, TLS or file bytes in this short synthetic capture cannot prove what happened outside it. DNS's authored answer, decoded request methods and port numbers do not establish request purpose, server delivery, incident attribution or an outcome for the original narrated case.


The direct export and native reference-frame checks now support repeated ports and per-packet SYN comparisons. The original malformed query remains only a malformed-query observation, not a checksum validation. No checksum-validity assertion is made. A separate authorized capture is required for TLS, response-body, downloaded-file or historical-case findings; none is substituted or inferred here. The learner's own recorded observations remain separate from this measured answer key.
