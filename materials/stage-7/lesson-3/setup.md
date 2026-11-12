# Setup and reproducibility

Use Python 3 and Wireshark with TShark and capinfos. Author verification used Ubuntu 24.04 and native Wireshark/TShark 4.4.0; see `tool-version.stdout.txt`. The PCAPs are ready to open; rebuilding is optional and sends no packets. Preserve originals: both builders refuse an existing output. Rebuild to NEW names in this folder:

```sh
python3 offline-builder.py --spec fixture-spec.synthetic.json --output rebuilt-ipv4.pcap
python3 ipv6-builder.py --output rebuilt-ipv6.pcap
```

Compare rebuilt SHA-256 against `expected-results.json`, then remove only your temporary rebuilds if desired. Actual verification included byte-identical IPv4 reconstruction and both existing-output refusal checks; see `execution-receipts.json`. Do not overwrite your own evidence. The IPv6 builder uses only `2001:db8::/32` addresses and standard-library deterministic packet assembly.

Run the same read-only observations as the author, with installed binaries on PATH:

```sh
tshark --version
capinfos -c -a -e -u practice.pcap
tshark -r practice.pcap -q -z endpoints,ip -z endpoints,ipv6 -z conv,ip -z conv,tcp
tshark -r practice.pcap -q -z "endpoints,ip,ip.addr == 192.0.2.10" -z "conv,ip,ip.addr == 192.0.2.10"
tshark -r practice.pcap -Y "ip.addr == 192.0.2.10 && tcp" -T fields -E header=y -e frame.number -e frame.len -e frame.cap_len -e tcp.len -e tcp.seq -e tcp.analysis.retransmission
tshark -r ipv6-practice.pcap -q -z endpoints,ipv6 -z conv,ipv6 -z conv,udp
```

Full exact actual arguments and outputs are retained in `execution-receipts.json` and matching stdout/stderr files. Relative TCP sequence fields depend on dissector preferences; raw sequence is `tcp.seq_raw`, recorded beside relative sequence in `frame-measurements.stdout.txt`.

Open `practice.pcap` in Wireshark. Confirm the file, 37 packets, UTC interval 2025-02-03 10:00:00 through 10:00:17.050, and clear display filter. Observation point is authored packet construction; no real collector location, drops, unseen directions, host applications or asset identity are established. Open Statistics → Endpoints, compare IPv4 address rows with TCP/UDP address-and-port rows, sort Bytes, and record Limit to display filter. Inspect IPv6 too; this file has none. Open Statistics → Conversations, compare IPv4 pairs with TCP and UDP tuples, sort Bytes, and record both direction labels, Start, Duration and limiting state.

Apply `ip.addr == 192.0.2.10`, reopen Conversations, and explicitly select Limit to display filter if needed. Record this scope separately. Right-click the TCP row for `192.0.2.10:54000` and `203.0.113.40:8080`; use Apply as Filter → Selected → bidirectional A ↔ B if that wording is offered in your version. Confirm the resulting expression selects both tuple directions and compare the packet list with `tcp.stream == 0` (12 frames). If your menu wording differs, manually enter `tcp.stream == 0` and record the manual route. Inspect frames 3–8 and 32–37. Clear the filter afterwards.

Open `ipv6-practice.pcap` as a separate file. Compare IPv6 address rows and UDP address-port rows; apply `ipv6.addr == 2001:db8::10`, verify limiting, and count each counterpart once. Do not combine the two independent captures into one observed environment or assume IPv4/IPv6 identities map to the same assets.
