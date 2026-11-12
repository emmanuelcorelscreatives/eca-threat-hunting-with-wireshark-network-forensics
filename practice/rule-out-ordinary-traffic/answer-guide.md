# Worked supplemental answer guide

These results come from the delivered synthetic file and actual local dissection, never the absent narrated case. First try the worksheet. The capture hash is `347dd60a86c07b556e1bc5082d36b6d4a2592adc707cca66d3d278cc2babf526`, 65 frames, from 2026-11-12 02:00:00.000000 through 02:03:03.020000 UTC. Both designed directions are visible. First/last times do not establish uninterrupted real capture coverage; there was no live collection.

The full unfiltered TCP Conversations table has these five rows. A is the lab asset (192.0.2.10), B the listed peer. Counts are full frames/bytes, not unique application content.

| Client port / stream | Peer and port | SYN frame / start UTC | Last frame / observed span | A→B frames / bytes | B→A frames / bytes |
|---|---|---|---|---|---|
| 41001 / 0 | 198.51.100.20:443 | 1 / 02:00:00 | 9 / 3.0200 s | 6 / 335 | 3 / 171 |
| 41002 / 3 | 198.51.100.20:443 | 27 / 02:01:00 | 35 / 3.0200 s | 6 / 335 | 3 / 171 |
| 41003 / 4 | 198.51.100.20:443 | 57 / 02:03:00 | 65 / 3.0200 s | 6 / 335 | 3 / 171 |
| 42001 / 1 | 203.0.113.30:8443 | 10 / 02:00:10 | 53 / 150.0200 s | 14 / 811 | 7 / 423 |
| 43001 / 2 | 203.0.113.40:9000 | 16 / 02:00:20 | 56 / 145.0200 s | 10 / 551 | 7 / 387 |

Update hypothesis: inventory maps the workstation and fictional configuration names the update peer and 02:00:00–02:01:30 UTC window. Starts in frames 1 and 27 fit that window; request/replies 4/5 and 30/31 show bidirectional exchanges. Frame57 starts a distinct out-of-window connection; 60/61 exchange data. The earlier match does not explain this later connection. No initiating process is identified by the PCAP or supplied owner statement. The port does not establish TLS, a real updater, or an approved executable.

Monitoring hypothesis: one SYN in frame10 opens stream1. Request/reply pairs are 13/14, 22/23, 36/37, 41/42, 46/47, at relative request times 11,41,71,101,131 seconds. Their 30-second spacing is within one 150.0200-second conversation, not five separate starts. Frames51–53 close it. Fictional enrollment/owner/endpoint records are compatible with monitoring but do not prove process attribution or approve all other traffic.

Keepalive hypothesis: the actual source expression selects probes 25,39,44,49 and reverse ACKs 26,40,45,50. Probes occur at relative 51,81,111,141 seconds: 30-second intervals within stream2. Setup is 16–18, prior payload19/20 with ACK21, close54–56. Raw sequence after the client's11-byte payload is5012; probe sequence5011 is one below that next sequence, with zero payload. Server next raw sequence13010 and the probe's ACK13010 agree. The reverse ACK acknowledges5012. The native GUI defaults to relative sequence numbers (probe Seq11, Ack10); those are not the raw values in the CSV. The labels explain idle probes within one existing connection. They establish neither its application purpose nor ownership. The owner record supplies no approved application for this peer.

I/O Graphs: the retained native graph uses All Packets at 1 second and also shows a TCP Errors series. A category label is not proof of malware. The [51,52) second bin contains frames25/26, a probe and its ACK, with zero new SYNs. The [60,61) bin contains27–29, three handshake packets for one new connection. The [61,62) bin contains30–32, payload exchange plus ACK on that connection. Always state your actual interval/filter/unit; the separate CLI60-second table is a different aggregation. Quiet bins cannot establish collection completeness.

A bounded conclusion: the designed asset configuration makes two within-window update connections and the monitoring lifecycle plausible ordinary explanations. The out-of-window update-peer connection remains unexplained. The keepalive pattern explains certain packets, while its connection's purpose/owner remains unknown. Initiating process identity is unknown for every stream. Unexplained is not proof of command and control.

Example next question: “Training IT, for LAB-WS-01 / 192.0.2.10 → 198.51.100.20:443, client port41003, observed 2026-11-12 02:03:00–02:03:03.020 UTC, was approved software configured to connect then, and are matching process-linked network events available?” Ask separately about the 203.0.113.40:9000 connection. Keep absent records and coverage gaps explicit.

Marking: require actual frame references, compatible event types, both directions, correct scope/time units, separate packet and administrative claims, the out-of-window exception, unknown process identity, and a limited follow-up. Do not award an all-benign or malicious verdict based only on timing or familiar peers.
