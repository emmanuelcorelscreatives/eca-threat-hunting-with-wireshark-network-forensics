# Trace collection and outbound transfer clues

This complete offline supplement practices the saved lesson with two independent synthetic observation points. It is not the unavailable staged case and does not assert that collection, an upload, SMB, TLS, or malicious intent occurred. No network traffic is sent. Use Python 3 standard library, Wireshark and TShark on your practice computer. No credentials, internet connection or production capture is required.

The ZIP includes both generated PCAPs, separate specifications, `offline_builder.py`, fictional mapping/calibration records, worksheet, checked key, decoded CSVs and actual execution receipts. Open each PCAP separately using File → Open. Retain each filename as a source identity; never merge away the observation-point distinction.

To reproduce, create a fresh empty output directory beside the downloaded kit, then from the kit directory run:

```text
python3 offline_builder.py --spec internal-spec.json --output rebuild/internal-observation.pcap
python3 offline_builder.py --spec edge-spec.json --output rebuild/edge-observation.pcap
tshark -r rebuild/internal-observation.pcap -q -z conv,tcp
tshark -r rebuild/edge-observation.pcap -q -z conv,tcp
```

Both captures were generated and decoded during production; `execution.json` contains exact commands, return codes, hashes and overwrite-refusal checks. Repeating into an existing output refuses to overwrite it; choose another new directory. Compare SHA256 using Python `hashlib` or your OS hash utility against `fixture-manifest.json`. Capture-file bytes, Ethernet frame bytes and TCP payload bytes are different measures.

In Wireshark set View → Time Display Format → UTC Date and Time of Day. Statistics → Capture File Properties shows source times and available capture metadata; legacy PCAP has no named interface description. Internally apply `ip.addr == 192.0.2.10` to retain both directions. At the edge first use `ip.src == 198.51.100.40` to isolate outbound traffic, then replace it with `ip.addr == 198.51.100.40` to inspect responses. Statistics → Conversations → TCP shows each tuple, counts, bytes and duration; clear Limit to display filter when comparing full capture totals. Select a TCP packet and use Analyze → Follow → TCP Stream, then close the dialog and clear its generated display filter to restore scope.

The clock checks and NAT table are explicitly authored fictional scenario records, not physical sensor measurements or actual equipment logs. `synthetic-nat-source.json` independently supplies the inside source-port mapping; it cannot be derived from the edge PCAP. The calibration uses recorded clock minus UTC: subtract +3 seconds at the edge, subtract zero internally. Both uncertainties are ±0.25 seconds. The interval between files remains entirely unobserved.

Existing lecture examples involving SMB operations or encrypted remote-service/TLS traffic remain examples requiring their own evidence. These HTTP and opaque TCP captures do not demonstrate them. Under an authorized encrypted case, metadata alone cannot identify a transferred item; any decryption requires authorized matching secrets and separate validation.
