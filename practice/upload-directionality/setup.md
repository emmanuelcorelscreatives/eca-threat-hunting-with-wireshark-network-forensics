# Setup and safe offline workflow

Use Wireshark4.4 or compatible, TShark/capinfos, and Python3.11+. Retain both delivered originals. Analyze working copies. `practice.pcap` and its identical `upload-directionality-synthetic.pcap` alias contain49 synthetic HTTP/FTP frames; `encrypted-session.pcap` contains15 actual loopback TLS1.2 frames. They have separate time windows and addresses; do not merge their identities or infer one continuous transfer.

From this extracted directory, run:

```sh
python3 generate_fixture.py --output scratch-http-ftp.pcap
python3 generate_fixture.py --spec fixture-spec.json --output scratch-http-ftp-explicit.pcap
capinfos -c -a -e -u practice.pcap
capinfos -c -a -e -u encrypted-session.pcap
tshark -r practice.pcap -q -z conv,tcp
tshark -r practice.pcap -Y 'http.request.method in {"POST", "PUT"}' -T fields -e frame.number -e tcp.stream -e ip.src -e ip.dst -e http.request.method -e http.content_length
tshark -r practice.pcap -Y 'ftp.request.command == "STOR"' -T fields -e frame.number -e tcp.stream -e ftp.request.command -e ftp.request.arg
tshark -r encrypted-session.pcap -d tcp.port==55451,tls -Y tls -T fields -e frame.number -e ip.src -e ip.dst -e tcp.len -e tls.record.content_type -e tls.record.length
```

The wrapper defaults to the adjacent fixture-spec.json; the builder refuses an existing output, including symlinks. It produces only the synthetic capture, sends no traffic, and does not regenerate the actual TLS session. SHA256 of the synthetic PCAP is `3474ec552efe6ff158fdc0718ac63f393f8aa762c819889f83ae86debe2f72db`; actual TLS PCAP is `0f3c468f54c19a6da16dc7633047b5006a6fd3ed30989e1c278b4b858efa5c4a`. Current execution receipts and decoder output are supplied; assembly-manifest.json is historical, with old prose/builder hashes. The separately supplied current-kit-inventory.json describes all final payload members; it excludes itself to avoid a recursive self-hash. It is delivered alongside those members.

Open practice.pcap in Wireshark. Open Statistics → Conversations, select TCP, and compare both captured directions. Apply the HTTP filter, select frame4, then Analyze → Follow → TCP Stream. Return to the packet list to inspect timing. Apply `ftp || ftp-data` and correlate PORT commands and data flows. Open Statistics → I/O Graphs, use the same interval and filter for comparison; the default packet graph counts packets. Select Bytes if comparing packet-byte totals, and record the chosen unit and interval.

For encrypted-session.pcap, select Analyze → Decode As, choose TCP port55451 as TLS, or launch `wireshark -d tcp.port==55451,tls -r encrypted-session.pcap`. Apply `tls.record.content_type == 23`. No decryption keys are supplied. Capture timestamps are UTC in the supplied CLI fields; set Wireshark View → Time Display Format to UTC Date and Time of Day for matching absolute times. Local loopback offload may expose unverified transport checksums; do not interpret that alone as corruption.
