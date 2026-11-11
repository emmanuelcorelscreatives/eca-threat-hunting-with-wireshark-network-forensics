# Follow a complete DNS transaction

Emmanuel Corels Academy · Threat Hunting with Wireshark: Network Forensics

Supplemental offline practice for Stage 9, Lesson 1. This synthetic exercise supports the saved lesson's query/response matching method. It does not claim to be a capture shown in the video, replace any demonstration that has no case file, or establish a real security incident.

## Files and setup

Download `captures/synthetic-dns-baseline.pcap`, `baseline-manifest.json` and this guide. Open the capture in Wireshark using File → Open. Disable external name resolution; the exercise needs no network connection or live collection.

The fixture can also be regenerated with Python 3, using only the standard library:

```sh
python3 tools/generate_baseline.py
```

The generator writes files under this exercise folder. It sends no packets. The MAC addresses are synthetic, the addresses are documentation examples and the names end in `.test`. The timestamp is a fixed synthetic exercise time, not a real collection record. The file represents a client-facing link between one synthetic client and its DNS resolver, with both directions included. It contains no upstream resolver traffic, host logs, application identity or later connections.

## Exercise

1. Confirm the file SHA-256 matches `baseline-manifest.json`; record the tool version.
2. Apply the display filter `dns`. Select frame 1 and record its endpoints, UDP ports, transaction ID, question name, type and class.
3. Locate its reply. Confirm the ID, question and reversed addresses/ports. Record the response code and answer section.
4. Repeat for the other two transactions. Record both frame references for every pair.
5. Explain which requester is visible at this stated capture point. Explain why an answer address alone does not prove a later connection, identify a user, or prove maliciousness.

For repeatable offline inspection:

```sh
tshark -n -r captures/synthetic-dns-baseline.pcap -Y dns -T fields -e frame.number -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e dns.id -e dns.flags.response -e dns.qry.name -e dns.a
```

## Worksheet

| Capture hash | Query frame | Reply frame | Client address/port | Resolver address/port | Transaction ID | Question/type/class | Response code | Answer type/value | Visibility limits |
|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | |

## Check your results

The file has six packets: three queries and three replies. Query/reply pairs are 1/2, 3/4 and 5/6. Transaction IDs are 0x1001, 0x1002 and 0x1003. Questions are `portal.academy.test`, `updates.academy.test` and `portal.academy.test`, respectively; each asks for an A record, class IN. The synthetic client is `192.0.2.10`, using ports 53000–53002. The resolver is `192.0.2.53:53`. Each successful reply contains the A answer `198.51.100.20`, with TTL 60 and a response 20 milliseconds after its query. These are verified properties of this generated fixture, not assumptions to apply to a different capture.

`baseline-validation.json` records the actual TShark validation: six packets, valid IP/UDP checksums, no malformed packets and identical bytes on regeneration. This fixture intentionally cannot establish the user's identity, whether a later connection happened, whether a resolver used its cache, or whether a host was compromised.
