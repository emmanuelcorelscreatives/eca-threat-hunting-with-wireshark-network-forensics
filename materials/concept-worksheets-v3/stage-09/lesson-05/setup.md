# Setup

## Scope
This is a supplemental, isolated exercise. No case capture or logs were supplied; do not produce a real endpoint finding. The repository baseline is synthetic and supports decoded-DNS field practice only. It establishes neither compromise nor a later connection.

## Required resources
1. Download or check out the course repository at verified commit `ef3b60b0094f19db99d7ac5160212ff3fc742fac`: <https://github.com/emmanuelcorelscreatives/eca-threat-hunting-with-wireshark-network-forensics>.
2. Read `practice/dns-baseline/README.md`. Before using the six-row worksheet and key, verify `captures/synthetic-dns-baseline.pcap` against SHA-256 `ff377b9bbe3c06df6ef68fe10b9beed6735421ae61b77330e59af574b0286e50` (also recorded in `practice/dns-baseline/baseline-manifest.json`); open that verified synthetic capture in an authorized working copy.
3. Use Wireshark for the packet exercise. TShark, capinfos, and the Python 3 standard library are maintainer-verification prerequisites, not student requirements for the written scenarios.

No other capture, case pack, credentials, or private data is required.

## Loading
Record the source filename before opening it. In Wireshark, note the displayed capture start and end and any documented capture point. Apply `dns`; this changes the view, not the packets. Record only decoded values actually displayed.

Use `tcp.port == 853` only to locate a clue. `ip.addr == 192.0.2.10` is a placeholder; replace it only with an endpoint recorded from an authorized source.

## Evidence-field dictionary
- **Source/window/point:** file, start, end, and observation location.
- **Coverage:** client-facing or upstream; interfaces and directions.
- **DNS fields:** frame, sender, receiver, response flag, transaction identifier, question name, and answer when present.
- **Assessment:** observed facts, unknown paths or times, candidate explanations, and requested record.

Use **unknown** when a value is unavailable; never manufacture it.