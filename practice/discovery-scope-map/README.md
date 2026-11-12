# Build a Discovery Scope Map — supplemental offline lab
This 14-frame synthetic Academy practice is separate from the unavailable case capture described in the saved lesson. It implements the gateway ICMP error omitted by the prior 13-frame draft. Documentation addresses replace draft 10.77.* addresses as recorded in collection-context.json. No original case findings or learner-owned capture are claimed.

Use Wireshark and LibreOffice Calc. Python 3.10+ standard library is needed only for optional offline rebuild; no pip dependency. TShark and capinfos are needed for CLI validation. All bundled execution receipts describe native Linux Wireshark/TShark 4.4.0; they are not Windows execution. No network traffic is sent by the builder.

Preserve source-original.pcap untouched. It has identical bytes to practice.pcap, which is supplied for analysis; make a separate work/ copy and open it in Wireshark. collection-context.json is hypothetical scenario context, not measured capture-path proof. Set View > Time Display Format > UTC Date and Time of Day. Check actual first/last timestamps against declared 2025-04-10 14:00:00–14:00:10 UTC window. Read record-availability.md. Complete worksheet.md and scope-map.csv, then compare answer-guide.md and expected-scope-map.csv.

From this directory, optional independent offline reproduction (new output required):
```
mkdir -p work
python3 build_fixture.py --spec spec.json --output work/rebuilt.pcap
cmp source-original.pcap work/rebuilt.pcap
python3 verify_fixture.py --spec spec.json --pcap source-original.pcap --expected expected-scope-map.csv
capinfos -c -a -e source-original.pcap
tshark -r source-original.pcap -n -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport
```
The builder refuses existing output, preserving originals. Delete only your own disposable rebuilt file before deliberately rerunning. Actual build, repeat/refusal, verification, full decode, checksum and malformed checks are retained in execution-receipt.json and corresponding CLI logs. The local supplemental kit is reviewed before publication to Academy practice/discovery-scope-map; this guide alone does not assert that publication occurred. The original lecture and case limitation remain unchanged.
