# Checked answer guide

Use `dns-fields.stdout.txt`, `tls-starts.stdout.txt`, `tls-fields.stdout.txt` and `tls-conversations.stdout.txt` to check references. All are actual decoder output from these exact files. DNS has 12 frames; TLS has 132 frames and six streams. Full capture hashes are in `execution-proof.json`.

DNS response frames 2 and 6 answer relay.case.test with 198.51.100.20 at 12:00:00.020 and 12:05:00.020 UTC. Frames 10 and 12 answer that same name with 198.51.100.21 at 12:10:00.020 and 12:15:00.020. Frames 4 and 8 answer manage.agent.test with 203.0.113.40 at 12:02:00.020 and 12:07:00.020. Their preceding odd frames are the matching questions, IDs 1001–1006. Each answer is NOERROR, A, TTL 60. The answers precede matching SYN starts by 19.990 seconds, inside that TTL, but DNS timing does not identify a process or prove lookup use.

| TLS stream | SYN frame | UTC start | source port | destination | host row |
|---|---|---|---|---|---|
|0|1|12:00:20.010|55001|198.51.100.20:443|H01|
|1|23|12:02:20.010|56001|203.0.113.40:443|H02|
|2|45|12:05:20.010|55002|198.51.100.20:443|H03|
|3|67|12:07:20.010|56002|203.0.113.40:443|H04|
|4|89|12:10:20.010|55003|198.51.100.21:443|none; outside coverage|
|5|111|12:15:20.010|55004|198.51.100.21:443|H05|

Every stream has 22 packets, twelve endpoint-to-server and ten server-to-endpoint, with .210-second captured duration. Three setup frames precede its ClientHello (frames 4, 26, 48, 70, 92, 114). Candidate SNI is relay.case.test; agent SNI is manage.agent.test. Captured TLS 1.2 opening metadata and two encrypted application records per stream are verified, but encrypted messages do not identify process, operator, commands or permission. The synthetic generator's purpose is disclosed provenance, not something an analyst can derive from encrypted packets. Candidate starts are 300 seconds apart; agent starts are also 300 seconds apart across only two samples.

Host rows are independent connect_attempt assertions. Endpoint, both addresses, ports and the constructed .010-second difference support H01/H03/H05 links to CaseWorker.exe for this exercise; H02/H04 link the separate agent sessions to ECADeviceAgent.exe. Packet visibility shows setup completion and TLS exchange; a host connect_attempt alone does not establish success. At 12:10:20 no host row exists because the excerpt has a documented gap, not proof no process event occurred. Do not infer a CaseWorker.exe row for that session solely from similar timing.

The supplied baseline asserts the agent is approved for manage.agent.test/203.0.113.40 in its stated role/window. That can explain the two agent sessions and weaken a C2 claim about them. It does not establish CaseWorker.exe approval or explain the candidate destinations merely because cadence matches. Other application behavior remains possible; shared infrastructure is a general alternative, not an observed additional endpoint in this fixture.

For a graph example, a one-second bin around 12:05:20 UTC identifies activity; original TLS frame 45 confirms the candidate SYN, and stream 2 supplies the peer tuple. Count independent SYN starts, not 22 packets or one graph bin. The IP filter for 198.51.100.20 yields streams 0 and 2 when the Conversations limit is enabled; all six remain available when disabled. Capture the actual GUI state and record selected graph units/interval in your own submission.

A defensible brief says candidate callbacks remain unexplained in the supplied excerpt, with source-backed DNS/session links and three matching host assertions, one gap, and no candidate approval. C2 purpose remains inconclusive: timing and encryption are insufficient. Request candidate software owner/approval and host telemetry around 12:10 first; ask for resolver/endpoint evidence if name-use attribution matters. Limit any candidate indicator to this endpoint and 12:00–12:16 UTC on 2025-01-16, preserve frame/row references and possible sharing/short lifetime. Do not label 203.0.113.40 suspected solely because it is nearby. Containment needs the response owner's evidence/impact decision, not automatic action from this lab.
