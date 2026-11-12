# Local setup and comparison commands

Run these from the downloaded kit directory. The Python commands send no packets.

## Verify and preserve

```sh
python3 generate_cases.py --verify --capture lesson-6-cases.pcapng --manifest case-manifest.csv
python3 -c "from pathlib import Path; import hashlib; print(hashlib.sha256(Path('practice.pcap').read_bytes()).hexdigest())"
```

Expected baseline SHA-256: `171c62e1bc91dfad4735175f4706a8ab715bb6d5d054bc950e41f5545c7711a4` (583 bytes). Richer capture: `3d4b9610390ff17b52b114eb9412718adf74c7f27695fc1bb7f4d6d7ceecff8e` (7112 bytes).

Optional rebuild into a new directory; choose a new name if it already exists:

```sh
python3 -c "from pathlib import Path; Path('learner-rebuild').mkdir(exist_ok=False)"
python3 offline-builder.py --spec fixture-spec.json --output learner-rebuild/baseline.pcap
python3 generate_cases.py --output learner-rebuild/cases.pcapng --manifest learner-rebuild/manifest.csv
python3 -c "from pathlib import Path; assert Path('practice.pcap').read_bytes()==Path('learner-rebuild/baseline.pcap').read_bytes(); assert Path('lesson-6-cases.pcapng').read_bytes()==Path('learner-rebuild/cases.pcapng').read_bytes(); print('Byte-identical')"
```

## Inspect version and preferences before interpreting

```sh
tshark --version > learner-version.txt
tshark -G currentprefs > learner-preferences-before.txt
```

Record your active GUI profile separately. Inspect `ip.defragment`, `ipv6.defragment`, `tcp.desegment_tcp_streams`, `ip.check_checksum`, `tcp.check_checksum`, and `udp.check_checksum`. Do not assume your defaults match the author environment.

## Find the evidence

```sh
tshark -r lesson-6-cases.pcapng -Y "ip.flags.mf == 1 || ip.frag_offset > 0" -T fields -e frame.number
tshark -r lesson-6-cases.pcapng -Y "ipv6.fraghdr.ident" -T fields -e frame.number
tshark -r lesson-6-cases.pcapng -Y "frame.cap_len < frame.len" -T fields -e frame.number
tshark -r lesson-6-cases.pcapng -o tcp.check_checksum:TRUE -o udp.check_checksum:TRUE -T fields -E header=y -E separator=, -e frame.number -e frame.cap_len -e frame.len -e ip.id -e ip.frag_offset -e ip.flags.mf -e ipv6.fraghdr.ident -e ipv6.fraghdr.offset -e ipv6.fraghdr.more -e tcp.seq_raw -e tcp.len -e tcp.checksum.status -e udp.checksum.status -e ip.reassembled_in -e ipv6.reassembled.in > learner-fields.csv
```

## Compare analysis settings

These available preference names permit explicit on/off comparisons. The following comparison runs are learner exercises, not supplied tested output claims.

```sh
tshark -r lesson-6-cases.pcapng -o ip.defragment:TRUE -o ipv6.defragment:TRUE -o tcp.desegment_tcp_streams:TRUE -o ip.check_checksum:TRUE -o tcp.check_checksum:TRUE -o udp.check_checksum:TRUE -V > learner-enabled.txt
tshark -r lesson-6-cases.pcapng -o ip.defragment:FALSE -o ipv6.defragment:FALSE -o tcp.desegment_tcp_streams:FALSE -o ip.check_checksum:FALSE -o tcp.check_checksum:FALSE -o udp.check_checksum:FALSE -V > learner-disabled.txt
tshark -r practice.pcap -o tcp.check_checksum:TRUE -T fields -E header=y -e frame.number -e frame.cap_len -e frame.len -e tcp.seq_raw -e tcp.ack_raw -e tcp.len
```

Change one preference at a time for causal comparisons after this combined contrast. CLI `-o` overrides apply only to that invocation; they do not save GUI preferences. After GUI experiments, export preferences again as `learner-preferences-after.txt`, record changes, and restore your original settings. Changed analysis never changes the sent packet or restores missing bytes.
