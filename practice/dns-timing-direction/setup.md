# DNS timing and direction practice

This separate Academy-designed synthetic offline lab supplements the lesson. The saved lesson supplies no case capture or incident findings. Use an authorized workstation with Python 3, Wireshark, TShark and capinfos installed; this kit contains no installers and makes no claim of learner installation. No network access or live capture is needed. All packet endpoints are documentation addresses and all names use reserved .test domains. Host rows are fictional metadata, not endpoint telemetry.

Keep the complete kit together. Open `practice.pcap` in Wireshark. Preserve its SHA-256 from `verified-results.json`. The builder sends no packets; to reproduce into a NEW file run from this directory:

```sh
python3 offline-builder.py --spec executed-fixture-spec.json --output rebuilt.pcap
capinfos -c practice.pcap
tshark -r practice.pcap -Y 'dns' -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e dns.flags.response -e dns.id -e dns.qry.name
tshark -r practice.pcap -Y 'dns && ip.addr == 192.0.2.10 && dns.flags.response == 0' -T fields -e frame.number -e dns.qry.name
tshark -r practice.pcap -Y 'dns && ip.addr == 192.0.2.10 && dns.flags.response == 1' -T fields -e frame.number -e dns.qry.name -e dns.a -e dns.aaaa -e dns.txt
```

Existing outputs are refused. Both specifications document the same scenario, but `executed-fixture-spec.json` is the actual builder schema. Local execution receipts and decoded fields are supplied. Native Wireshark workflow: open the PCAP, select View → Time Display Format → UTC Date and Time of Day; apply `dns`, then the case-host filters. Statistics → I/O Graphs: add separate request and response filters from above, Packets units, one-second interval, then 100 ms. Inspect packet pairs behind each burst. Graph bytes include overhead and repeats and are not candidate text volume. Record filter, interval and frame references. This workflow is an exercise, not a claim a learner has performed it. Complete worksheet.md before consulting the key.

Collection scope is a designed client/resolver link, 2025-02-05 09:00:10–09:01:01.600 UTC. Resolver upstream, address ownership, live endpoint clock offset, process identity and compromise are not established. Do not infer missing traffic never occurred.
