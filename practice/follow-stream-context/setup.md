# Setup and exercise

Extract the full ZIP and open a terminal in its directory. The included TCP and UDP captures are ready to open. To reproduce the original classic PCAP bytes without overwriting them:

```sh
python3 offline-builder.py --spec tcp-follow-context.synthetic.json --output my-tcp.pcap
python3 offline-builder.py --spec udp-follow-context.synthetic.json --output my-udp.pcap
```

Choose fresh output names. The builder refuses an existing output. It uses documentation-only IPv4 addresses and creates files offline; it starts no capture and sends no traffic. Supplied CLI evidence records byte-identical rebuilds and actual refusal tests.

```sh
capinfos -c -a -e -u tcp.pcap
capinfos -c -a -e -u udp.pcap
tshark -r tcp.pcap -q -z follow,tcp,ascii,0
tshark -r tcp.pcap -q -z follow,tcp,hex,0
tshark -r udp.pcap -q -z follow,udp,ascii,0
tshark -r udp.pcap -q -z follow,udp,hex,0
```

Open tcp.pcap in Wireshark. Record the current time-display format; the default relative format measures from frame 1. The specifications and epoch fields give UTC times. Apply `ip.addr == 198.51.100.20`, select frame 2 and record its source and destination ports. Use Analyze → Follow → TCP Stream (Linux shortcut Ctrl+Alt+Shift+T). Read Entire conversation, then each direction using the lower-left selector. Change Show as from ASCII to Hex Dump; this changes representation, not what was captured. Restore ASCII and Entire conversation.

Choose Close. Inspect the actual `tcp.stream eq 0` filter and frames 2–5. Record times and direction. Restore your original address filter before opening Follow again; choose Back. Verify the original address filter returns. Clear it and inspect all six frames, including the different-endpoint ICMP context.

Open the separate udp.pcap. Apply `ip.addr == 198.51.100.21`, select frame 2 and use Analyze → Follow → UDP Stream (Ctrl+Alt+Shift+U). Compare combined, individual-direction and Hex Dump views. Treat the four contributions as separate datagrams. Close and inspect `udp.stream eq 0`, frames 2–5 and their times/directions. Restore your prior filter before reopening Follow and choosing Back; verify the returned address filter. Clear it and inspect all six frames. An index of 0 in each separate file does not join the cases.

Complete worksheet.md. Do not infer delivery, processing, intent or causality from packet proximity or opposite direction. Filtering cannot restore packets never captured. Hex does not decrypt encrypted content. Request additional capture coverage or contextual telemetry when needed. Reassembly and Decode As are the next lesson's subjects, not a repair implied by this lab.

## Reading order and uncertainty

Follow TCP places captured bytes in expected sequence order for reading. The packet list records the packets as captured, with their times and directions. These views answer different questions. Compare them before explaining a pause, apparent repeated data or a Wireshark retransmission label. Investigate sequence numbers, both directions and observation-point coverage; a label alone is not a diagnosis. These fixtures do not contain an authored retransmission, so do not invent one.

UDP guarantees neither delivery nor protection from duplicate datagrams. If a direction is absent, this capture cannot distinguish a datagram never sent from one not captured. Grouping contributions in Follow does not resolve this uncertainty.

After the supplied practice, apply the worksheet to an offline capture you are authorized to inspect, if you have one. Record its actual filename, local stream index and limits afresh; do not transfer these fixture results or claim this supplied synthetic file is a capture you collected. If no other authorized file is available, complete the supplied synthetic exercises and mark the separate personal-capture extension as not performed.
