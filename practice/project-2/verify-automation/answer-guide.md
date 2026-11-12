# Checked packet observations and answer guide

These observations come from the delivered synthetic captures and actual TShark 4.4.0 execution, with separate real Linux GUI screenshots. They do not describe the unavailable historical Project 2 case. Source identities and coverage are in manifest.json; actual command stdout/stderr and repeated runs are retained.

| Selection | sensor-a | sensor-b | Unit |
|---|---:|---:|---|
| Whole file | 9 | 17 | packets |
| dns | 2 | 2 | displayed packets / exported packet rows |
| http | 2 | 4 | displayed packets / exported packet rows |
| http.response | 1 | 2 | displayed packets / exported packet rows |
| conv,tcp with no separate filter | 1 | 2 | conversation rows |
| conv,tcp,dns | 0 | 0 | conversation rows |
| endpoints,ip,dns | 2 | 2 | endpoint rows |

The unfiltered conversation statistic still reports TCP conversations when the main selection is -Y dns. Its own explicit dns filter yields no TCP conversations. DNS endpoint rows each count their involvement in the same two packets, so summing their packet counts double-counts packets. Equal row totals do not make endpoint and packet units interchangeable. -c 1 reads one packet; that first packet is not HTTP in either source, so the supplied read-limit HTTP outputs are empty despite later HTTP packets.

H1: sensor-a frame 8 and sensor-b frame 9 decode as HTTP 200 responses at 2025-02-03 09:00:00.150 UTC, from 198.51.100.20:80 to 192.0.2.10:54000. Both have Set-Cookie values a=1 and b=2. The all-occurrence export gives a=1|b=2; the first-occurrence control gives a=1. One spreadsheet value does not prove only one protocol occurrence. Empty request-method and DNS fields in these response rows reflect missing fields in those packets, not absent packets.

H2: the sources share authored exchange times and application payloads, but their frame numbers and IPv4 IDs differ because the separate builder enumerates each input's events. sensor-a request frame 6 corresponds to the shared authored request at sensor-b frame 7; response references are 8 and 9. This is synthetic scenario correspondence, not measured real-world sensor provenance. Never link files from equal frame numbers. The checked derivative mapping matches each merged packet's actual timestamp and exact captured bytes against all source candidates. In this kit those matches are unique; if multiple exact matches existed, the verifier and mapping require all candidates and leave the unique reference empty. Interface IDs are retained as supplementary metadata and are not the sole matching rule. No merged packets were deduplicated: 9 + 17 = 26.

H3: sensor-b frame 16 is HTTP 204 at 09:00:00.350 UTC, from 198.51.100.21:80 to 192.0.2.11:54100. sensor-a ends at 09:00:00.160; sensor-b covers 09:00:00.001 through .360. Absence of that later response from the first source does not establish packet loss or malicious activity. These are authored coverage windows, not a measured clock correction. Actual clock offset is unknown.

H4: dns selects frames 1–2 in sensor-a and 2–3 in sensor-b. Whole-file totals include TCP, and sensor-b also has its leading UDP background packet. The displayed count differs from the captured total because filtering hides packets. Requests, replies and ACK context remain in the source. For example source-a request frame 6, ACK frame 7, response frame 8 and ACK frame 9 show more context than a response-only export.

All eight full exported selections (four per source) were rerun and their exact normalized TSV bytes matched. tools/verify.py recomputes every listed hash, source frame totals, every derivative mapping row from actual bytes/timestamps, export copies, repeat equivalence, repeated cookie values and empty malformed outputs without writing files. This supports reproducibility within the supplied environment; it does not prove the investigator's wider interpretation. Preserve disagreements as inconclusive when source coverage, command settings or a supported mapping cannot resolve them.
