# Setup

Download the complete folder. Use Python3 and Wireshark/TShark4.4.0 in an authorized offline workspace. The builder uses Python standard library modules only. Run commands from this folder. Existing files are preserved by the versioned generator; use a fresh output path.

```text
python3 generate_column_hunt_fixture.py --output build/column-hunt-synthetic.pcap
python3 generate_column_hunt_fixture.py --verify build/column-hunt-synthetic.pcap --expected expected-results.json
```

If tshark is outside PATH, add `--tshark /absolute/path/to/tshark` to verification. Verify checks exact SHA256,20frames, the HTTP Host/method pair, TLS SNI, two DNS answer values, and absence of malformed dissection. actual-validation.json records the author's execution; learner execution is a separate task. The baseline can be rebuilt with `python3 offline-builder.py --spec fixture-spec.json --output build/practice.pcap`; that older builder overwrites its output, so always choose a new path.

Open column-hunt-synthetic.pcap. Disable automatic network name resolution; do not start capture. Clear the display filter. Create a dedicated practice profile and retain normal Time, Source, Destination, and Protocol columns. Open Edit → Preferences → Appearance → Columns on Linux/Windows; on macOS the Preferences entry is under Wireshark. Only Linux4.4.0 was executed here. Add Custom rows with these titles and fields:

| Title | Field |
|---|---|
| TCP Stream | tcp.stream |
| UDP Stream | udp.stream |
| DNS Question Name | dns.qry.name |
| DNS Response Name | dns.resp.name |
| HTTP Host | http.host |
| HTTP Method | http.request.method |
| TLS Server Name | tls.handshake.extensions_server_name |

Use Field Occurrence 0 to display all occurrences,1 for the first,2 for the second. Resize/reorder columns to retain readable normal context; scroll horizontally if needed. Packet Details is the authority when a cell is blank or truncated. Screenshots use a compact proof profile with seven custom fields; students must retain the normal contextual columns in their own profile.
