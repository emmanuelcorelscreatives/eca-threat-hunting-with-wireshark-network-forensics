# Offline setup

Use a computer with Wireshark, TShark and Python 3 installed through your normal approved software source. Save and extract the whole kit into a writable local folder. Open a terminal in that folder; Windows may use `python` rather than `python3` and must put the installed TShark directory on PATH. Check `python3 --version` and `tshark --version`; keep your own versions with your results. The recorded CLI and native GUI versions may differ; see the execution receipts for their actual identities.

Run `python3 verify_fixture.py`. It must exit successfully and print `"status": "pass"`; stop and keep the error if it fails. This verifies the supplied file against its manifest and structural/packet checks, then uses actual TShark dissection. No live network access is made.

Optional exact offline rebuild: `python3 generate_fixture.py --spec fixture_spec.json --output rebuilt.pcap`. Choose a new output filename; the generator refuses an existing file. Compare SHA-256 against the capture hash printed by the verifier using `sha256sum rebuilt.pcap` (Linux) or `Get-FileHash rebuilt.pcap -Algorithm SHA256` (PowerShell). The recorded execution demonstrates one byte-identical rebuild and refusal to overwrite it. Never overwrite the supplied input or edit an evidence receipt to force a pass.

In Wireshark choose File → Open and select `supplemental_ordinary_traffic.pcap`. Do not start a live capture. Clear any display filter. The full file has 65 frames. Set View → Time Display Format → UTC Date and Time of Day when comparing the configuration's UTC windows; relative times start at 02:00:00 UTC. You can inspect relative times for intervals without changing the underlying timestamps.

Open Statistics → Conversations and choose TCP. Record whether Limit to display filter is selected. With an empty display filter the full set contains five conversations; a checked limit with a nonempty filter can change the set. Inspect both directional packet/byte columns, Start and Duration; scroll horizontally if necessary. Native screenshots record the actual supplied Linux build, while your layout may differ.

Open Statistics → I/O Graphs. Begin with All Packets and a 1 second interval to inspect bursts; if the UI chooses another interval, record it explicitly. Packet counts are not connection starts. Return to packets to confirm event types. The delivered `io-60seconds.txt` is a separately executed 60-second CLI packet aggregation, not a claim about the native graph's interval.

Apply `tcp.analysis.keep_alive || tcp.analysis.keep_alive_ack`, then inspect surrounding packets by `tcp.stream == 2`. Use `frame.number == 25` to inspect the first probe. The displayed original frame number is retained under filtering. Restore the full capture by clearing the filter when comparing all connections. Do not infer process, software identity, or approval from labels, ports, intervals, or a familiar peer.
