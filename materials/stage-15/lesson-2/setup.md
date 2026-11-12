# Supplemental DNS measurement lab

This complete offline Academy exercise is synthetic and separate from the unavailable narrated case. It simulates three comparable workstations and resolver 192.0.2.53 at a client-facing observation point during [2025-01-16T12:00:00Z, 2025-01-16T12:01:00Z). Roles and control designations are authored metadata. No real application, user, incident or complete device activity is established.

Extract the complete kit into a working folder. Files use flat paths: inventory.tsv and events.tsv are inputs; practice.pcap is the unfiltered supplied capture. DATA_DICTIONARY.md describes fields; worksheet.md is the exercise; answer-guide.md and execution.json supply measured results. These names replace earlier draft proposals for nested fixture/scripts paths. Open practice.pcap in Wireshark. Preserve the original and record each display filter. Use Python 3.11 or newer and TShark for the optional reproducibility checks below; the recorded execution used the versions in tool-versions.txt. No network or case access is required.

Run from the extracted directory:

```sh
python3 --version
tshark --version
python3 build_fixture.py --inventory inventory.tsv --events events.tsv --out rebuilt.pcap
python3 check_fixture.py --inventory inventory.tsv --events events.tsv --pcap practice.pcap --rebuild-and-compare
```

The builder refuses to replace any existing output. Choose a fresh filename for another rebuild. The checker decodes all 43 messages independently with TShark, verifies each TSV row, calculates query/response pairs and totals, rejects malformed frames and compares a fresh rebuild byte for byte. execution.json records the actual supplied capture run; negative-checks.json records rejection of truncated, modified and empty captures and existing builder output. Neither constitutes proof of your own execution.

Check available fields with `tshark -G fields` and search for dns.qry.name, dns.qry.name.len, dns.qry.type, dns.flags.response and dns.flags.rcode. The recorded build exposes all five. A different build may lack optional dns.qry.name.len: record that limit and measure ASCII labels separately. The supplied CLI receipt is an actual local run, not a claim that GUI actions were performed. Complete the GUI steps yourself and retain frame/filter evidence.

Use an isolated offline working copy. Install Wireshark/TShark from the official Wireshark distribution or your operating system package manager, and Python 3 from python.org or your operating system package manager. Confirm local capture-reading permissions; no live capture is needed. Required release gate: do not publish dependent visuals or exports until fixture and answer-key verification succeeds. This supplied version has the recorded successful verification.
