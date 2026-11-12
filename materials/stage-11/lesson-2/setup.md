# Setup and reproducibility

Use an offline copy of this kit. Install Python 3 and Wireshark/TShark through your organization's approved process if absent. Run `python3 --version`, `wireshark --version`, and `tshark --version` (on Windows, Python may be `py -3` and tool executables may need their installed paths). Tool installation and Windows behavior are not claimed as tested. Author execution used Linux and Wireshark/TShark 4.4.0; exact recorded commands and outputs are in `execution-receipts.json`. Tool paths in receipts identify the author's binary, not a required learner location.

From this extracted directory, first validate the supplied capture:

```sh
python3 verify_fixture.py --plan packet_plan.csv --metadata capture_metadata.json --pcap failed_partial_synthetic.pcap
```

Expected: `verified: true`, 14 frames, 1036 filesystem bytes, SHA-256 `d759cb6bfb220bd5ae4a9105e210b712689165e805a758d2253084607e5ff42c`. The raw reader checks packet order, timestamps, lengths, IPv4/TCP/ICMP checksums, endpoint fields and E1/F1 quotations. To rebuild safely, choose an absent filename; the generator refuses to overwrite an existing file:

```sh
python3 generate_fixture.py --plan packet_plan.csv --metadata capture_metadata.json --output rebuilt.pcap
python3 verify_fixture.py --plan packet_plan.csv --metadata capture_metadata.json --pcap rebuilt.pcap
```

The author rebuilt to a scratch path and verified byte identity, existing-output refusal and four corrupt scratch-file rejections; results are in `execution-receipts.json`. The original generation command (recorded with actual stdout) used `--output failed_partial_synthetic.pcap` before that file existed. Do not rerun it against the delivered file.

Open Wireshark and choose **File → Open**, then select `failed_partial_synthetic.pcap`. Record the filename, emulated observation point, and packet timestamp window. The synthetic point is a client-facing link near 192.0.2.10, not measured coverage. The declared scenario window is 12:00:00–12:00:07 UTC on 2025-01-16; first/last encoded packets are 12:00:00.000 and 12:00:06.020 UTC. Display times may use local timezone; set a UTC display or cite UTC from the supplied decoded output. No live capture is required. No traffic is sent.

Paste these display filters one at a time, then clear the filter to inspect both directions and nearby frames:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.reset == 1
(icmp.type == 3) || (icmpv6.type == 1)
((tcp.flags.syn == 1 && tcp.flags.ack == 0) || (tcp.flags.reset == 1) || (icmp.type == 3) || (icmpv6.type == 1))
```

Expand the IPv4/ICMP packet details of frames 12 and 14 yourself. Inspect each quoted original IPv4 header and TCP ports/sequence. Eight quoted TCP bytes contain ports and sequence, not TCP flags. IPv6 is a method pivot only; this fixture contains no IPv6. A narrow SYN/error filter hides SYN-ACK and ACK packets without deleting them.

Reproduce the CLI pivots if TShark is available:

```sh
tshark -r failed_partial_synthetic.pcap -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport
tshark -r failed_partial_synthetic.pcap -Y 'tcp.flags.reset == 1' -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport
tshark -r failed_partial_synthetic.pcap -Y '(icmp.type == 3) || (icmpv6.type == 1)' -T fields -e frame.number -e ip.src -e icmp.type -e icmp.code -e icmpv6.type -e icmpv6.code
tshark -r failed_partial_synthetic.pcap -Y 'icmp.type == 3' -V
```

These exact arguments were run with the author's absolute TShark binary. Outputs are `syn`, `reset`, `icmp` and `icmp-verbose.stdout.txt`. ICMP `ip.src` may show outer and quoted inner IP addresses separated by a comma; use the verbose tree to distinguish them. Unix single-quote syntax shown above also works in PowerShell; adapt shell quoting if using cmd.exe. No Windows execution proof is asserted.
