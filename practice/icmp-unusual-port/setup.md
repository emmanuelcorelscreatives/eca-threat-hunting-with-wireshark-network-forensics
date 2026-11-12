# Setup and reproduce

Download the whole offline kit, extract it, and open a terminal in its `icmp-unusual-port` directory. Use Python 3 and Wireshark/TShark 4.4 or a compatible newer version. No network capture privileges are required. Recorded author commands used native Linux Wireshark4.4.0 on Ubuntu24.04; another version's layout or automatic protocol labels can differ.

```sh
python3 -m json.tool fixture-spec.json
python3 verify_fixture.py --spec fixture-spec.json --pcap practice.pcap
python3 offline-builder.py --spec fixture-spec.json --output rebuilt.pcap
python3 verify_fixture.py --spec fixture-spec.json --pcap rebuilt.pcap
```

`rebuilt.pcap` must be a new path; the builder refuses any existing destination. The original `practice.pcap` remains unchanged. Compare SHA256: both must be `7bfea53ad900a1fb583cadf5ad5a05d2e3909f5110f17f2ec4b61172fe43cc15`. The verifier reads raw PCAP/Ethernet/IP/transport bytes without importing the builder, checks checksums, exact payloads, timestamps, endpoints and quoted-header equality. It does not establish a real service owner or malicious purpose.

Open `practice.pcap` with File > Open in Wireshark. Keep original frame numbers when filtering. The status must show 34 total packets. Time zero is 2025-01-15 12:00:00 UTC; relative times in the answer guide refer to that first packet. For absolute times, select UTC Date and Time of Day explicitly in View > Time Display Format and record your choice. Never mistake a relative timestamp for UTC.

For your own case, obtain authorization, make a working copy, record its SHA256, capture point, time window and zone, address translation, missing directions and truncation. These remain learner tasks and are not fulfilled by this synthetic kit. Do not transmit the fixture onto a network.
