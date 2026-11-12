# Setup and safe replay

Use a local course checkout or extracted offline kit. No network access, administrator privileges, production capture, credentials, TLS secrets, Python packages or connection to the documentation addresses is required. These addresses are offline labels. Recommended learner UI: Wireshark 4.4.0 on Windows 11, English and light theme, matching the lecture. Actual supplied execution was on Ubuntu Linux with TShark 4.4.0; Windows-specific launch syntax below is a learner instruction, not a claimed Windows test.

1. Keep all delivered files together under `practice/hidden-flow/`. Read the provenance in README.md before interpreting packets. Open `hidden-flows.pcapng` through File → Open. Retain an unfiltered view for context.
2. Optional exact rebuild: run `python rebuild_capture.py rebuilt-hidden-flows.pcapng` from this directory. It consumes only the colocated packet-records.json and writes a new file. Existing output is refused. Compare its SHA256 to `03c3948f8c555da158828dc269d83e4c126460bd36d776c5e89f0380ffb42e49`. The delivered file is 15,840 bytes and has 76 Ethernet frames. On Windows use `Get-FileHash .\rebuilt-hidden-flows.pcapng -Algorithm SHA256`. Do not overwrite the supplied capture. A modified input must fail the pinned hash check.
3. Choose View → Time Display Format → UTC Date and Time of Day. For this synthetic fixture, timestamps span 2025-01-16 12:01:00 through 12:12:00 UTC. This is authored time, not a host collection clock. There is no actual collection point; both synthetic directions are supplied by construction. The intended asset alias is 192.0.2.10. Real homework requires an independently justified device mapping and collection scope.
4. Apply `ip.addr == 192.0.2.10`; inspect traffic in both directions. Open Statistics → Conversations and select TCP. Compare all four rows. Clear “Limit to display filter” when establishing complete fixture totals. Record whether start times are relative or absolute. The CSV inventory service label is hypothetical context, not packet attribution.
5. Open Statistics → I/O Graphs. Compare filters `ip.addr == 198.51.100.20` and `ip.addr == 203.0.113.40` with Y axis Packets, the same interval and no other filter. Start at 1 second, then 3 minutes (180 seconds). If a build does not offer an exact interval, use the actual CLI io,stat outputs for that interval and record the difference. Click a graph time range and inspect the associated packets. A final endpoint exactly on a bin boundary may have a separate boundary bin; count packets rather than estimating graph height.

The following two saved-plan commands can be run from a Windows checkout root. The exact capture and equivalent Linux TShark arguments were executed; exit status and output are in execution.json. PowerShell invocation itself was not executed here.

```powershell
& "$env:ProgramFiles\Wireshark\tshark.exe" -n -r "practice\hidden-flow\hidden-flows.pcapng" -q -z conv,tcp
& "$env:ProgramFiles\Wireshark\tshark.exe" -n -r "practice\hidden-flow\hidden-flows.pcapng" -Y "dns || tls.handshake.extensions_server_name || quic" -T fields -e frame.number -e _ws.col.Protocol -e tls.handshake.extensions_server_name
```

The second output is empty for this fixture, not a failed command. Inspect `tls.handshake.type == 1 || tls.handshake.type == 2` to see actual hello messages, including TLS1.3 supported-version fields. Record observed fields; do not invent a certificate, hostname, ECH outcome or protected request. Do not load keys or attempt decryption.
