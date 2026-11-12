# Port and host fan-out — offline Academy lab

This separately authored synthetic exercise supplements Stage 11 Lesson 1. The saved lecture has no supplied capture; these 12 packets are not historical incident evidence. No network traffic is generated. Use Wireshark 4.4 on Ubuntu 24.04 in English. Open `practice.pcap` offline; do not start Capture. All files in this folder travel together. Read `capture-context.json`, `DATA_DICTIONARY.md`, then `worksheet.md`; consult `answer-key.md` after your attempt.

The delivered Python 3 standard-library builders send no packets and refuse to overwrite files. From this folder, reproduce with a fresh output path:

```sh
python3 offline_builder.py --spec fixture-spec.json --output rebuilt-spec.pcap
python3 build_fixture.py --plan packet-plan.csv --output rebuilt-plan.pcap
cmp rebuilt-plan.pcap practice.pcap
python3 verify_fixture.py --plan packet-plan.csv --capture practice.pcap --context capture-context.json --expected expected-checks.json
```

These correspond to the previously planned `scripts/build_fixture.py`, `scripts/verify_fixture.py`, `data/packet-plan.csv`, `fixture/port-host-fanout-synthetic.pcap`, `data/schema.md` and `answer-guide.md`: the delivered names are `build_fixture.py`, `verify_fixture.py`, `packet-plan.csv`, `practice.pcap`, `DATA_DICTIONARY.md`, `answer-key.md`. No duplicate paths are required. `execution.json` records actual Linux CLI verification and decoding; GUI steps below are learner instructions unless separately documented by native receipts. No Windows execution is claimed. The capture has no application payload, process identity or approval record. Public publication is a separate step.

Native supplemental screenshots and native-execution.json document actual Linux4.4 open, exact port/host filters, TCP Conversations and Statistics > I/O Graphs (Alt+S, I). I/O Graphs shows all packets plus the filtered-attempt series at a one-second interval; compare the filtered series to packet references. The Conversations view is limited to the broad source traffic filter; its five TCP conversations are not a unique-port or target count. The corrected native right-scroll view shows stream IDs, relative starts, durations and packet direction; its address columns are outside the view. Use the actual open packet list and decoded rows to map tuples to stream order. Graph filter columns were widened and the graph table scrolled to expose the full filter expression.
