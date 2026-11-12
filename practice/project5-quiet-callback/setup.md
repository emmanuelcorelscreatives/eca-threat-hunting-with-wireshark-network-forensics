# Setup, source identity, and scope

Use Python 3 for optional byte-exact reconstruction, Wireshark for the GUI investigation, and TShark/capinfos for optional verification. No network connection, interface capture, credentials, administrative privilege, key log, or TLS decryption is needed. Work from a new copied folder and keep source captures unchanged.

The topology is authored: `lab-win11-01` at `192.0.2.10`, DNS resolver `192.0.2.53`, candidate destinations `198.51.100.20` and `198.51.100.21`, approved agent `203.0.113.40`. Both captures represent the same endpoint-side link without NAT. This mapping is scenario metadata, not discovery of real hosts. Addresses use documentation networks, names use `.test`. Real-world NAT, shared services, missing lookups, caching and asymmetric collection still need investigation; do not transfer this mapping to another capture.

All authored timestamps are UTC. `dns.pcap` has six question/answer pairs from 12:00:00 to 12:15:00.020 on 2025-01-16. `tls.pcap` contains six complete synthetic TCP sessions starting 12:00:20.010, 12:02:20.010, 12:05:20.010, 12:07:20.010, 12:10:20.010, and 12:15:20.010 UTC; each spans .210 seconds, ending no later than 12:15:20.220. Sparse authored packets do not establish continuous collection. The clocks are assigned to the same synthetic time basis. The supplied host timestamps are .010 seconds before the corresponding SYN by construction; this is not a measured clock offset or permission to correct timestamps. Certificate validity reflects generation time, not the historical authored packet timestamps; this is not evidence of an expired production certificate.

Host excerpt coverage is H-A 12:00–12:08 and H-B 12:14:30–12:16 UTC, with a gap. The absent host row at 12:10:20 falls in that gap. Baseline rows assert exercise approval for ECADeviceAgent.exe and describe only their supplied window. They do not establish a general schedule or prove candidate-process approval.

Open `dns.pcap` with File → Open. Apply `dns`. Select an answer, expand Domain Name System in Packet Details, and record its query, transaction ID, response status, A address and TTL. Open `tls.pcap` separately with File → Open, retaining original file/frame references. Use `tls` initially, then an observed IP address. A TLS display filter hides SYN/FIN-only frames; use `tcp.stream == 0` or clear the filter to inspect transport setup. View → Time Display Format → UTC Date and Time of Day makes the time basis explicit.

For six conversation rows, clear the display filter, open Statistics → Conversations and choose TCP. Record peers, ports, packets, start time and duration. Toggle Limit to display filter only after applying `ip.addr == 198.51.100.20`, then compare the two matching sessions with the unfiltered six. Verify rows against original SYN frames. Under Statistics → I/O Graphs, use a suitable interval to find activity windows; graph counts are packets or bytes, never a count of separate check-ins. Return to the packet list and inspect the start frames. Native Linux evidence and its limits are in `native-validation.md`; menu placement can vary by version and Windows behavior is not asserted as tested.

Optional exact reconstruction (creates a new output directory and refuses any existing directory):

```sh
python3 rebuild_capture.py --output-dir rebuilt-captures
capinfos -c -a -e -u rebuilt-captures/dns.pcap rebuilt-captures/tls.pcap
tshark -r tls.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e frame.number -e frame.time_epoch -e tcp.stream -e tcp.srcport -e ip.dst
```

`replay-records.json` contains approved original wire bytes and hashes, including actual encrypted TLS records. Replay reproduces bytes; it does not initiate TLS or collect traffic. The original DNS-only draft's unavailable TLS and proposed `--build`/`--verify` commands are superseded by this delivered, executed reconstruction workflow; they were never executed. Do not run those unsupported historical commands.
