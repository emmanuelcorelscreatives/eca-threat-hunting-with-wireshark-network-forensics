# Executed synthetic answer guide

These observations come from the delivered 24-frame synthetic PCAP and executed TShark/raw checks. They are not findings from the unsupplied historical case. Frame and stream numbers apply only to this exact file; bind it with the SHA-256 in independent-pcap-report.json.

The actual first frame is 2025-02-12 10:00:30.000000 UTC; the last is 10:10:05.040000 UTC. The host/time bound [10:00,10:10) keeps frames 1–21 and excludes frames 22–24. Sparse timestamps do not prove continuous observation. The candidate-specific bound keeps frames 3–9 and 20–21.

Frames 1 and 2 are the client 10.77.0.15 and resolver 10.77.0.53 UDP exchange, client port 53000, transaction 8705, query relay.academy.test. Frame 2 at 10:00:30.020 has both A answers 198.51.100.44 and 203.0.113.80 in one DNS response, TTL 300. This supports a name-to-address correlation at this observation point, not process ownership or common endpoint control.

Candidate stream 0, client port 54000 to 198.51.100.44:443, consists of frames 3–9 at 10:01:00.000–.120. Frames 3–5 show SYN, SYN/ACK and ACK; frames 6–9 close it. No TLS or application bytes are supplied. Calling this encrypted content would go beyond the packets.

Possible peer stream 1, client port 55000 to 203.0.113.80:80, frames 10–16 at 10:01:02.000–.120, has a handshake and visible HTTP. Frame 13 contains `GET /status HTTP/1.1` with Host relay.academy.test and 50 payload bytes. Frame 15 has HTTP 200 OK, Content-Length 2, body OK, and 40 payload bytes. The request next sequence is 3051; response acknowledgment is 3051; the client acknowledgment after the response is 12041. DNS plus actual visible Host supports a bounded relationship worth retaining, while shared infrastructure or ordinary management remains possible. It proves no command-and-control purpose.

Incidental stream 2, client port 56000 to 192.0.2.81:80, frames 17–19 at 10:01:03.000–.040, has only a handshake. There is no supplied independent DNS/application link. Nearby timing is insufficient: leave it off the related-session shortlist.

Candidate stream 3, client port 54001 to 198.51.100.44:443, frames 20 and 21 at 10:04:00 and 10:04:01, repeats SYN sequence 2000 on the same five-tuple. TShark marks frame 21 a retransmission. This is one attempt with a retry and no captured response, not two check-ins and not proof of blocking. It differs from established stream 0 despite sharing an address pair.

Control stream 4, client port 57000, frames 22–24 at 10:10:05.000–.040, establishes a handshake outside the exclusive interval. It must not appear in the bounded shortlist. The bounded TCP Conversations CLI output contains streams/ports for four in-window TCP conversations; address-pair summaries can combine the two candidate flows.

A defensible output retains candidate streams 0 and 3 as distinct transport observations and stream 1 as a DNS/application-correlated peer; it separates unsupported stream 2 and excludes stream 4. Record source/hash, frames, times, scope and uncertainty for every entry. Ask for process-network telemetry, approved-agent baseline, observation coverage or NAT attribution only where needed to test a specific remaining link. No supplied data resolves those questions. Restore the host/time filter after Follow and carry only these packet-supported relationships into the next timeline exercise.
