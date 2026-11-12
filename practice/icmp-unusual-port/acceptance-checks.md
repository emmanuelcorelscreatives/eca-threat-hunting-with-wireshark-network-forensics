# Reproducible acceptance checks

Run from the extracted kit directory. These are the agreed current relative paths. Historical absolute maintenance paths are provenance only, not learner commands.

```sh
python3 verify_fixture.py --spec fixture-spec.json --pcap practice.pcap
tshark -n -r practice.pcap -Y 'icmp' -T fields -e frame.number -e ip.src -e ip.dst -e icmp.type
tshark -n -r practice.pcap -Y 'icmp.type == 8 || icmp.type == 0' -T fields -e frame.number -e icmp.ident -e icmp.seq -e data.data
tshark -n -r practice.pcap -Y 'icmpv6.type == 128 || icmpv6.type == 129' -T fields -e frame.number -e ipv6.src -e ipv6.dst -e icmpv6.type -e data.data
tshark -n -r practice.pcap -Y 'tcp.port == 8443' -T fields -e frame.number -e tcp.srcport -e tcp.dstport -e tcp.flags -e tcp.stream
tshark -n -r practice.pcap -Y 'tcp.dstport == 8443' -T fields -e frame.number
tshark -n -r practice.pcap -Y 'udp.port == 8443' -T fields -e frame.number -e udp.srcport -e udp.dstport
tshark -n -r practice.pcap -Y 'udp.dstport == 8443' -T fields -e frame.number
tshark -n -r practice.pcap -q -z conv,tcp -z conv,udp
tshark -n -r practice.pcap -q -z follow,tcp,ascii,0
tshark -n -r practice.pcap -Y 'frame.number == 34' -V
```

Expected: verifier PASS34records/2627filesystem bytes/2059packet bytes; full ICMP filter includes IPv4 Echo1–10 and error34; IPv6 filter31–32; TCP8443 nine frames11–19; destination TCP11,13,14,17,18; UDP8443 frames29,30 and destination29; whole-file conversation results and Follow Stream match answer guide. No malformed frames are expected. Compare payload hex, not only packet labels. Raw verifier checks the exact28-byte frame33 quote in34 and all supplied Echo payload matches.

Author execution in `execution.json` includes actual deterministic rebuild, existing-output refusal, corrupt-copy verifier refusal, filters, complete decoded fields, Conversations, Follow Stream and verbose error output. Native PNGs separately evidence visible GUI actions; decoded hidden fields are not GUI observations. Students should perform the worksheet GUI walkthrough themselves and record their actual labels/time settings. A passing verifier is fixture correctness, not a security verdict or evidence that a learner captured traffic.
