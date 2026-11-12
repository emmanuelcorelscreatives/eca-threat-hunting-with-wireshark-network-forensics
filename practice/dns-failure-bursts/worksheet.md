# Worksheet — failures, bursts and repeated lookups

Work first from the two supplied verified PCAPs. Use the design CSV only to cross-check the model after observing packets. Record native results from your actual version. If you later repeat the method on an authorized capture of your own, treat that as a separate investigation; no learner-owned capture has already been collected for you.

Capture filename and SHA: __________  Collection point: __________  First/last timestamp and time basis: __________  Applied filter: __________

Hypothesis: __________  Competing explanation: __________

| Original frame(s), separate file | Name/type/class | Query endpoints/ports; ID | Query/reply time | Reply code, answers/authority, or no visible reply |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |

1. Start with `dns`. Match at least one positive A exchange, one NXDOMAIN exchange, and the NOERROR, zero-answer AAAA response with SOA. Compare name, type, class, ID, endpoint tuple and direction. Use actual frame references; CSV row IDs are not frames. Explain why a query without a visible response is not NXDOMAIN.
2. Use `dns.flags.response == 1 && dns.flags.rcode == 3`. Record client-facing replies and upstream replies separately. In Statistics > DNS inspect Response, rcode and Query Type groups. Identify which counters count BOTH requests and responses; record the filter and do not call every rcode-zero packet a successful answer.
3. Inspect `known.lab.test` A versus AAAA, and expand the latter reply's authority SOA. Record answer/authority counts, zone, TTL and MINIMUM. What could negative caching explain, and what evidence is missing before saying a cache hit occurred?
4. Compare `svc.lab.test` and `svc.office.test`. State why shared base names and close timing make suffix expansion a hypothesis rather than proof of a configured search list. Compare `oldsvc.lab.test`, `known.lab.test`, and `retry.lab.test` across transactions.
5. Apply `dns.retransmit_request || dns.retransmission`. Manually compare matched queries with earlier requests by name/type/class, tuple, ID and timing. Does a heuristic establish the responsible process, a server failure, or malicious intent? Record uncertainty.
6. In I/O Graphs plot the exact NXDOMAIN response filter, Y Axis Packets, in 1-second then 200-ms intervals. Record actual filter, intervals and units. Inspect frames underlying the first peak. State the time origin separately for each file. Do not compare the upstream short window to the entire client window as equal coverage.
7. Use the table below to compare application errors, stale configuration, resolver architecture/cache behaviour and an unresolved security lead. Request only one specific corroborating record that could change your conclusion.

| Packet observation and frame/file | Application hypothesis | Configuration/resolver hypothesis | Missing evidence/security lead |
|---|---|---|---|
| | | | |
| | | | |

Outcome **explained / worth further investigation / unresolved**: __________

Confidence and capture limits: __________

One specific next evidence request: __________

A later own-data exercise may use a permitted offline capture: record its provenance and repeat the method without importing this key's counts or frame numbers. The next lesson considers unusual names and record types; do not infer those findings here.
