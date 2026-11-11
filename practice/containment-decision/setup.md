# Setup and Supplemental Case

**Release gate:** Assign the packet portion only after the Academy publishes and execution-verifies the complete download pack: `setup.md`, `worksheet.md`, `answer-guide.md`, `supplemental-scenario.md`, `fixture-spec.json`, `build_synthetic_connection.py`, and `synthetic-connection.pcap`. No PCAP output, packet count, timestamp, conversation, hash, or successful run is asserted here.

Use the saved environment: Windows 11, Wireshark 4.4, English, light theme. Students need no Python. Before publication, release staff must regenerate offline and inspect the result:

```powershell
py -3 -m json.tool fixture-spec.json
py -3 build_synthetic_connection.py --spec fixture-spec.json --output synthetic-connection.pcap
```

These are unexecuted instructions here, not evidence of success.

## Preserve and inspect

1. Keep the verified PCAP as the practice original. Make and open a separate analysis copy; overwrite neither.
2. Record identifying details and calculate each file’s actual hash:
   ```powershell
   Get-FileHash -Algorithm SHA256 -LiteralPath 'synthetic-connection.pcap'
   ```
3. In the copy, inspect Capture File Properties for identity and time coverage. Inspect Conversations for observed systems, timing, and counts—not maliciousness.
4. Apply `tcp`, record the visible result, then clear it. A display filter does not change the original capture.
5. Record the capture point and directions seen or missing. Traffic beyond that point is unknown.

## Explicitly synthetic case

This fictional exercise is unrelated to Project 7. Scenario metadata—not packet-derived facts—uses case `SYN-21-04-01`, endpoint `LAB-WS-01` (`192.0.2.10`), peer `LAB-PEER-01` (`198.51.100.20`), client port `49152`, peer port `443`, and a client-facing capture point. The intended design is an Ethernet/IPv4/TCP no-payload handshake with a fixed synthetic `start_utc`; treat that design as unobserved until inspection. TCP port 443 alone does not establish encryption.

Fictional service-catalog context—not packet evidence—says `SVC-01` may use the same peer. Endpoint role, account, process, other routes, compromise, approvals, supporting records, and retention deadline remain unestablished.

**Field dictionary:** IDs label synthetic entities; IPv4 values are documentation addresses; capture-point and service-catalog fields are scenario metadata; null fields mean unknown, not absent.