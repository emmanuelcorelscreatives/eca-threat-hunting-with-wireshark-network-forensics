# Offline setup and safe reproduction

Use Wireshark with permission to inspect these synthetic files. Python 3 and TShark are needed only for optional rebuild and command checks. No administrator privilege, live capture, credentials or private traffic is required. Record your Wireshark version (Help > About Wireshark), operating system, original file source and capture SHA-256 before analysis. Native author screenshots use Linux Wireshark 4.4.0; your layout may differ.

Work in the extracted kit folder. The builder refuses existing output files. Create a fresh temporary directory and preserve the delivered originals:

```sh
LAB_REBUILD=$(mktemp -d)
python3 offline-builder.py --spec fixture-spec.json --output "$LAB_REBUILD/baseline.pcap"
python3 offline-builder.py --spec limited-fixture-spec.json --output "$LAB_REBUILD/limited.pcap"
cmp supplemental-session-patterns.pcap "$LAB_REBUILD/baseline.pcap"
cmp supplemental-visibility-limits.pcap "$LAB_REBUILD/limited.pcap"
python3 check_capture.py .
tshark -r supplemental-session-patterns.pcap -q -z conv,ip -z conv,tcp -z conv,udp
tshark -r supplemental-visibility-limits.pcap -Y 'frame.cap_len < frame.len' -T fields -e frame.number -e frame.cap_len -e frame.len
```

Successful cmp emits no output. The author executed equivalent commands against the supplied files, with byte-identical fresh rebuilds. Existing execution logs use author absolute paths and do not need to exist on your machine. Open the local PCAP using File > Open; do not use Capture > Start.
