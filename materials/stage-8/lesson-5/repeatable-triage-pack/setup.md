# Setup and preserve originals

Use an authorized isolated practice directory with Python 3 standard library, Wireshark GUI, TShark, capinfos and a POSIX shell. This offline lab does not require network capture. Extract the whole kit and run commands from its root. Inspect paths-manifest.csv. Each source ID identifies a separate immutable input and a separate writable working path. Its capture points, coverage and UTC clock basis are authored scenario metadata, not evidence of real collector coverage or synchronization.

Create fresh outputs; stop if results/ already contains a prior run. Do not replace existing results or originals. Keep the originals under inputs/originals/. Record OS, actual tool versions, GUI profile and name-resolution setting. Worked native evidence used an isolated default profile, UTC and disabled name resolution.

```sh
mkdir -p results/work results/regenerated results/per-source results/per-source-labeled
for id in point-a point-b point-c; do
  mkdir -p "results/$id"
  cp -n "inputs/originals/$id.pcap" "results/work/$id.pcap"
done
tshark -v
capinfos -v
python3 -c 'import platform; print(platform.platform())'
```

Record originals and work-copy hashes with capinfos -H for every source, then compare with evidence/source-log.json. The copies must match their own originals; do not compare a derivative hash with an original hash. The independent byte checker reads the actual originals and verifies record bounds, counts, IPv4/TCP checksums, payload lengths, raw acknowledgments and cross-source mappings:

```sh
python3 check_originals.py
```

Optional deterministic regeneration writes only to fresh scratch paths:

```sh
for id in point-a point-b point-c; do
  python3 offline_builder.py --spec "$id.json" --output "results/regenerated/$id.pcap"
done
```

Compare the reported SHA-256 with that source's published original. The builder refuses an existing output instead of replacing it. Three original-refusal tests and byte-identical regeneration runs are recorded in evidence/execution.json. The JSON input implementation replaces the earlier proposed CSV-input generator; there is no scripts/generate_synthetic_pack.py. The supplied label_and_sort.py provides the earlier labeling/sorting objective at the actual documented paths. Do not use the old draft command or assume its files exist.
