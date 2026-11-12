# ARP, DHCP and local discovery — supplemental packet lab

This Academy-authored synthetic lab supplements the unchanged lecture's no-case-file interface rehearsal. It is not historical incident evidence. Both independent traces are supplied and decoded: client-facing-synthetic.pcap (17 frames) and relay-server-side-synthetic.pcap (2 frames). There is deliberately no ambiguous practice.pcap alias. No live traffic, production network or credentials are required.

Use this complete directory at `practice/arp-dhcp-local-discovery/` in the Academy course repository. README.md is setup, DATA_DICTIONARY.md is schema, worksheet.md is the exercise and answer-guide.md is the worked solution. No alternate setup/SCHEMA/solutions filename is required. Publication and download auditing are separate release checks.

Install Python 3.11+ and Wireshark/TShark through your approved local packages. The generator needs only Python's standard library. From this directory run:

```sh
python3 generate_fixture.py --out-dir regenerated
python3 verify_fixture.py --input-dir .
```

Windows: replace `python3` with `py -3.11`. Set TShark on PATH. The generator refuses to overwrite either existing PCAP. Generation is offline and sends no packets. Verification writes decoded CSVs and actual-execution.json into its input directory; use a writable offline working copy. The supplied execution receipt records actual Ubuntu TShark4.2.2 validation, not a claimed Windows or GUI run.

Open client-facing-synthetic.pcap using Wireshark File > Open. Enter `arp`, inspect operation and sender/target hardware and IPv4 fields, then use `dhcp` and inspect transaction/client/relay/options. Use `udp.port == 5353` and inspect decoded query/response/payload, including deliberately malformed frame12. Open the relay PCAP independently and use `dhcp`. Display filters hide other frames without deleting them. Complete worksheet.md before consulting answer-guide.md. GUI steps are learner instructions; no instructor GUI execution is asserted.

The client trace's synthetic selected client-port mirror and relay trace's separate bidirectional server-link mirror are collection scenarios, not proof of real collection coverage. Read capture-context.csv first. A packet identifies network messages, not process identity, authorization or whole-subnet silence. printer.local is an Academy-authored supplemental example. Malformed frame12 is an intentional counterexample: its UDP port does not establish valid mDNS.
