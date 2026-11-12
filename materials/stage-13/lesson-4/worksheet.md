# Direction, size and reuse worksheet

1. Record filename, SHA-256, synthetic provenance, simulated client-facing capture point, UTC start, your display time format and Wireshark version. Inspect the full baseline before filtering.
2. Compare `ip.addr == 192.0.2.40` with `ip.src == 192.0.2.40`. Explain which reverse traffic the latter hides. Restore the first filter.
3. Open Statistics > Conversations. Record the Limit to display filter checkbox state. Compare IPv4 and TCP tabs, both addresses and ports, directional packets/bytes, start and duration. Explain why one IP-peer row does not imply one connection or one application request. Repeat a one-direction limited comparison and restore both directions.
4. Apply `ip.addr == 192.0.2.40 && ip.addr == 198.51.100.25 && tcp`. Inspect SYN/SYN-ACK/ACK and closing flags with original frame references. Compare `tcp.stream == 0`, `tcp.stream == 1`, and `tcp.stream == 2`. Identify separate connections and activity recurring within one connection. Apply `tcp.stream == 2 && http.request`; distinguish two visible requests from fourteen transport packets.
5. In stream 2 inspect activity across its duration. Open Statistics > I/O Graphs, set a filter for `tcp.stream == 2`, record interval and Y-axis units, compare 1-second with 10-second intervals for the explicit purpose of seeing aggregation. Check original packets around apparent peaks and quiet spans. Do not count peaks as requests or infer reliable coverage from a quiet graph.
6. Inspect `udp && ip.addr == 192.0.2.40 && ip.addr == 203.0.113.9`. Record observed datagrams and directions without assigning application purpose or TCP connection language.
7. Check `tcp.analysis.retransmission` and `frame.cap_len < frame.len` in each file. Open the limited derivative separately. Compare its first connection with the baseline and its truncated record with the full counterpart; record local frame numbers for each. Interpret expert indications as visibility questions. A missing response does not prove the server did not send one.
8. Write a bounded assessment separating observed direction/size, connection reuse, application visibility and uncertainties. Include ordinary possible explanations (maintenance, monitoring, idle traffic), ownership/asset context, possible NAT or path limitations and a confidence statement. No ratio, duration or peer count establishes command-and-control.

| File/source and capture point | UTC scope/time display | Exact filter/checkbox state | Observation and original frames | Directional counts/bytes and units | Separate interpretation | Confidence and missing context |
|---|---|---|---|---|---|---|
| | | | | | | |

For your own capture, use only an authorized copy. Record its genuine provenance and sensor/time/coverage limits, substitute its scoped host/peer addresses, and repeat the evidence table. The supplied synthetic worked example does not fulfill this personal task. State whether activity crosses separate TCP connections or reuses one; describe only visible messages. Bring a packet-backed observation and unresolved ownership question to Rule Out Updates, Monitoring and Keepalives, without assuming a benign or malicious answer.
