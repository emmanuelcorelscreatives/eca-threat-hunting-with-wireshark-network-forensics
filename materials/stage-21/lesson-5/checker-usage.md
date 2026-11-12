# Independent raw packet checks

This offline Python 3 checker reads classic Ethernet PCAP bytes independently of the builder. Run from the extracted kit directory:

```sh
python3 check_capture.py --spec pre_action-spec.json --capture pre_action.pcap
python3 check_capture.py --spec post_action-spec.json --capture post_action.pcap
```

A successful run prints a JSON frame list, capture SHA-256 and byte length and exits zero. A disagreement exits nonzero; do not treat partial output as approval. It validates record lengths, timestamp equality, IPv4 and transport checksums, endpoints, TCP flags and sequence/acknowledgment values, and payload against every specified event. It does not establish real collection coverage, control enforcement, packet provenance beyond the supplied fixture, or application identity. The specification remains an authored fictional design.

`independent-check-execution.json` retains actual local executions, two byte-identical rebuilds, and eight scratch-only rejection tests: truncation, bad checksum, changed timestamp and wrong spec for both captures. `existing-output-refusal.json` shows the delivered builder refuses an existing output file; create a fresh scratch directory for rebuilding. Never overwrite a downloaded original.
