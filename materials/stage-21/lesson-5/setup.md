# Offline setup and evidence preservation

## Prerequisites
Have Python 3, Wireshark and TShark available locally. No particular version is required. Commands below use a POSIX shell; use a local terminal supporting it. Do not capture live traffic or run as root for this exercise. Put all supplied source files in one flat local directory and run commands there.

## Fresh scratch directory, reconstruction and copies
Never overwrite originals. `mkdir scratch` must succeed; if scratch already exists, stop and use a new exercise directory rather than reusing it. The supplied packet specifications are data; the builder sends no packets. Because binary PCAPs are reproducible from these supplied specifications, build them in scratch, not over any source capture.

```sh
mkdir scratch
python3 build_capture.py --spec pre_action-spec.json --output scratch/pre_action.pcap
python3 build_capture.py --spec post_action-spec.json --output scratch/post_action.pcap
python3 - <<'PY'
import hashlib, json
from pathlib import Path
m = json.loads(Path('capture_manifest.json').read_text())
for c in m['captures']:
    p = Path('scratch') / c['file']
    b = p.read_bytes()
    assert len(b) == c['bytes'], p
    assert hashlib.sha256(b).hexdigest() == c['sha256'], p
    original = Path(c['file'])
    if original.exists():
        assert original.read_bytes() == b, original
    print(c['captureId'], len(b), hashlib.sha256(b).hexdigest(), 'verified')
PY
python3 build_capture.py --spec pre_action-spec.json --output scratch/pre_action-rebuilt.pcap
python3 build_capture.py --spec post_action-spec.json --output scratch/post_action-rebuilt.pcap
cmp scratch/pre_action.pcap scratch/pre_action-rebuilt.pcap
cmp scratch/post_action.pcap scratch/post_action-rebuilt.pcap
cp scratch/pre_action.pcap scratch/pre_action-working.pcap
cp scratch/post_action.pcap scratch/post_action-working.pcap
cp control_record.csv scratch/control_record-working.csv
cp coverage.csv scratch/coverage-working.csv
```

Successful `cmp` commands print nothing and establish byte-identical rebuilds. Hash expectations are 900 bytes / 17901d9f8b619c7c060a001597b82e453c16122c9fecc8b9e4e92d43c94195cd for pre and 1178 bytes / 6a25fbdbf72b5f4af33926b6a1521adbc9ecdeaf95a43845ec08539476e33f1a for post. Stop on any failed assertion or comparison.

## CLI inspection
These are learner reproduction commands, not a claim of new execution. Existing execution.json records successful supplied CLI runs and their fuller field lists. Preserve supplied CSVs; write new output only into fresh scratch.

```sh
for phase in pre post; do
  tshark -r scratch/${phase}_action-working.pcap -o tcp.check_checksum:TRUE -o udp.check_checksum:TRUE -o ip.check_checksum:TRUE -T fields -E header=y -E separator=, -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags -e tcp.seq_raw -e tcp.ack_raw -e tcp.len -e tcp.payload -e udp.srcport -e udp.dstport -e ip.checksum.status -e tcp.checksum.status -e udp.checksum.status > scratch/${phase}-decoded.csv
  tshark -r scratch/${phase}_action-working.pcap -Y '_ws.malformed || ip.checksum.status == 0 || tcp.checksum.status == 0 || udp.checksum.status == 0' -T fields -e frame.number > scratch/${phase}-bad-frames.txt
  tshark -r scratch/${phase}_action-working.pcap -q -z conv,tcp > scratch/${phase}-conversations.txt
done
```

Expect 12 pre and 16 post packet rows. Compare field values with the supplied decoded CSVs. Supplied empty bad-frame files and execution.json report no malformed frames or bad checksums; this validates fixture decoding, not real-world containment.

## GUI learner instructions — not executed evidence
1. Separately select **File → Open** and open `scratch/pre_action-working.pcap`. Do not merge captures. Record its source identity LAB-CV-PRE-01 and manifest hash.
2. Select **Statistics → Capture File Properties**. Record packet count, first/last packet times and available interface information. Classic PCAP does not establish the scenario collection point; consult coverage.csv separately.
3. Measure display offset: set an absolute date/time display, record the displayed time for pre frame 1, then switch to UTC date/time and record the same frame's UTC time (2025-01-15 11:57:00). Compute local minus UTC, including date rollover, and record the workstation zone. An already UTC display has offset zero; do not assume another workstation's offset. Preserve original epochs; never shift evidence to fit an action time.
4. Separately use **File → Open** for `scratch/post_action-working.pcap`. Repeat Properties and time reconciliation with post frame 1 (12:05:00 UTC). Associate it with LAB-CV-POST-01.
5. Use the filters and Statistics tasks in the worksheet. Record source capture plus original frame number; display filtering does not renumber source frames. Graphs and tables guide inspection, not replace packet evidence.