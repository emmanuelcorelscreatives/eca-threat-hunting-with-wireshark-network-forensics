# Predict, filter, inspect, clear

**Question:** Can a display filter retain a known relevant *exercise candidate* while excluding a known benign exercise control? In the supplied synthetic PCAP, treat the decoded report-CSV GET as the candidate, the manual-PDF GET as the benign control, and the POST containing `reporting` as an incidental text control. These are **authored roles, not incident findings**. No capture was supplied with the original lecture; do not transfer these labels or frame numbers to another file.

Source I actually opened: __________  SHA-256 checked: __________  Decoder/version: __________  GUI/OS, if used: __________

1. **Establish references with the filter clear.** Consult `packet-manifest.csv`, then expand Packet Details to identify the report GET, reporting POST, manual GET, DNS query and answer, a TCP SYN and SYN-zero ACK, and both sides of the port-443 exchange. The supplied Linux field log identifies corresponding frames **6, 11, 16, 1–2, 3 and 5, and 18–20 in this particular `practice.pcap`**. Verify each in your own opened file before recording it as an inspected reference. Inspect decoded method and full URI, both TCP ports, and the SYN value where available. If an expected HTTP field is absent, clear the filter and check the packet's decoding; do not assign its planned role to a different packet merely to complete the exercise.

2. **Predict first, then apply each expression individually.** Enter it in Wireshark with Enter or Apply, note whether the candidate and both controls remain, inspect a displayed packet's actual decoded field, then clear the filter and inspect a hidden reference. Observation cells remain intentionally blank for the learner. The separate measured key and actual Linux/Windows execution evidence now record these selections; do not copy them into a claimed personal observation.

| Test | Exact expression | My predicted included/excluded references | My observed frames, fields and surprises |
|---|---|---|---|
| Method exists | `http.request.method` | __________ | __________ |
| Decoded GET | `http.request.method == "GET"` | __________ | __________ |
| Decoded other method | `http.request.method!= "GET"` | __________ | __________ |
| Whole-test negation | `!(http.request.method == "GET")` | __________ | __________ |
| URI substring | `http.request.uri contains "report"` | __________ | __________ |
| URI extension and optional query | `http.request.uri matches r"\.(csv|pdf)(\?.*)?$"` | __________ | __________ |
| TCP port exists | `tcp.port` | __________ | __________ |
| Either port is 443 | `tcp.port == 443` | __________ | __________ |
| Every present port differs | `tcp.port!= 443` | __________ | __________ |
| Whole-test negation | `!(tcp.port == 443)` | __________ | __________ |
| Occurrences in one frame | `count(tcp.port) == 2` | __________ | __________ |
| Explicit every-occurrence test | `all tcp.port!= 443` | __________ | __________ |
| SYN field exists | `tcp.flags.syn` | __________ | __________ |
| SYN value is set | `tcp.flags.syn == 1` | __________ | __________ |

For methods, compare a GET, the POST and a packet without a decoded request method. `!= "GET"` requires the field; `!(... == "GET")` can retain a missing-field packet. For URI tests, read the **full** `/reports/report.csv?rev=1`, `/status/reporting.txt` and `/public/manual.pdf` strings where decoded. Why is `reporting` an incidental substring, and why can the benign PDF satisfy the extension regex? `contains` applies to compatible text/bytes, not a numeric or IP-address search; `matches` uses PCRE2, ignores case by default, and the raw quotes protect the backslashes. An absent decoded URI cannot be found by either test.

For ports, inspect both source and destination values on the port-443 exchange and on a port-80 request, then compare the DNS control. Predict equality from either occurrence; check that `!=` and `all ... !=` require every present occurrence to differ, whereas negating equality can include packets with no `tcp.port`. `count` counts occurrences **in one frame**, not distinct numbers or conversations. A 443 match establishes a decoded port, not TLS, purpose, who initiated the flow, or maliciousness. For flags, compare the decoded SYN subfield on the known SYN with the ACK control: field presence is not the value 1. If results disagree with the reference, investigate decoding and file identity rather than changing your hypothesis to fit a green filter bar.

3. **Test the actual inclusion/exclusion objective.** The 14 expressions expose different scopes; neither GET alone nor the saved extension regex separates the report candidate from the benign PDF in this fixture. Propose and, in your GUI, test `http.request.method == "GET" && http.request.uri contains "report"`. Predict the candidate and both controls separately; inspect all three with the filter cleared afterward. This composite was also executed on the supplied fixture and selected frame 6 alone. It is a measured teaching example, not a general detector: it could miss relevant non-GET or undecoded requests and could include an unrelated GET containing that substring. If it fails in your decoder, document the failure and revise only after examining the actual fields.

4. **Keep the investigation question richer than a filter exercise.** Check the decoded DNS question and advertised answer, the four TCP conversations, HTTP request fields, raw TCP sequence/ACK and payload lengths, and the complete file again. Record what the saved packets establish and what they do **not**: no logged HTTP response code or `http.file_data`, no observed downloaded CSV/PDF contents, and no TLS-decoded packets in this fixture. A port-443 handshake cannot answer a TLS, file-transfer or incident-attribution question. Are the requests relevant activity, and was any file served? Leave those findings unresolved without separately authorized evidence. For an actual narrated-case conclusion, obtain and examine that case's capture; this synthetic file cannot replace it.

For **each** filter or case claim, write: question and predicted positive/control; exact expression; inspected source filename and frame references; decoded field values; displayed and hidden results; alternative explanation; confidence limit; next useful action. Keep packet bytes (`frame.len`), TCP payload bytes (`tcp.len`) and any hypothetical file-content bytes separate. Note whether your result came from the supplied Linux logs, your own GUI inspection, or a prediction you have not yet tested. Clear the filter at the end: it restores only packets saved in this file. The next lesson, *Add Columns That Answer the Hunt Question*, makes useful fields easier to see.