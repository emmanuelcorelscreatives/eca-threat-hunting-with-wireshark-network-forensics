# Setup and reproducible inspection

Use an ordinary user account and authorized offline files. The target teaching environment is Ubuntu 24.04, English light-theme Wireshark 4.4. The retained author evidence is native Linux Wireshark/TShark 4.4.0; no Windows execution is claimed. The builder creates synthetic packet bytes offline and sends no packets. No live collection is needed for this supplied exercise.

## Preserve and identify the input

Keep the original `practice.pcap` unchanged. Record its filename and SHA-256, then make a separate working copy and record that copy's filename and SHA-256. Verify they match before analysis. For this fixture only, the approved original digest is `741a40d9c1d1d3e3361b2bc4a670b9a5cd7d2e3b1e9d60d215d356b6e9417eb4`. A hash mismatch is a stop condition; it is not a reason to edit a source file until a checker passes.

The physical file is **2,378 bytes**, containing **33 records** and **1,826 captured frame bytes**: `24 + 33 * 16 + 1826 = 2378`. The recorded Linux 4.4 classic-PCAP Properties window shows a separate **2,362-byte Length** counter. `native-file-accounting.json` explains its 16-byte difference; do not infer truncation from it. First and last packets are **2025-01-16 12:00:02.000000 UTC** and **12:01:02.060000 UTC**, a **60.060-second** observed span. File precision is microseconds. Extra displayed decimals do not add precision or prove clock accuracy.

## Optional safe rebuild

Use Python 3 and the delivered `offline-builder.py` with `executed-fixture-spec.json`. The current builder opens the output with exclusive creation (`xb`) and refuses an existing path. Rebuild into a fresh temporary directory, never over a supplied file:

```sh
set -eu
sha256sum practice.pcap offline-builder.py executed-fixture-spec.json
rebuild_dir=$(mktemp -d)
python3 offline-builder.py --spec executed-fixture-spec.json --output "${rebuild_dir}/practice.pcap"
sha256sum practice.pcap "${rebuild_dir}/practice.pcap"
cmp practice.pcap "${rebuild_dir}/practice.pcap"
```

This is a learner recipe, not a claim that the literal block was recorded on their machine. `builder-safety-and-rebuild-execution.json` records the actual matching fresh rebuild and refusal tests for this builder and source. A printed builder digest is not an independent check. Leave all originals intact if any step fails. Do not use the older proposed `build_fixture.py`, absent `timing-supplement.pcap` alias, unexecuted `timing-supplement.json` spec alias, or nonexistent `--check` option. The historical manifest retains those earlier contexts without making them current instructions.

## Independent checker and read-only CLI

Follow `checker-usage.md` to parse the PCAP separately from the builder. The recorded checker validates the actual bytes and spec; it does not authorize inspection or establish collection coverage. Keep current `independent-pcap-*` results distinct from the older historical manifest.

Optional reproduction commands, run from a directory containing your working copy, are:

```sh
capinfos practice.pcap
tshark -r practice.pcap -T fields -E header=y \
  -e frame.number -e frame.time_epoch -e frame.time_utc -e frame.len -e frame.cap_len \
  -e frame.protocols -e ip.src -e ip.dst -e tcp.stream -e tcp.srcport -e tcp.dstport \
  -e tcp.seq_raw -e tcp.ack_raw -e tcp.len -e tcp.payload \
  -e dns.qry.name -e dns.qry.type -e dns.a -e http.request.method \
  -e http.request.uri -e http.host -e http.response.code -e http.file_data
tshark -r practice.pcap -q -z conv,tcp
tshark -r practice.pcap -q -z conv,ip
tshark -r practice.pcap -q -z io,phs
tshark -r practice.pcap -Y _ws.malformed -T fields -e frame.number
```

The retained logs record source-built 4.4.0 executables and their own argv, rather than a verified learner PATH. The original export lacks decoded flags/checksum fields; the later `decoded-fields.stdout.csv` and its execution record supply them. `frame.time_utc` is UTC text; `frame.time_epoch` is decimal epoch seconds. `frame.time_iso8601` was not supported in the pinned field inventory. An empty malformed-frame result does not establish zero packet loss or healthy collection. Optional keep-alive classification must not be claimed from an export that did not request that analysis field.

## Native GUI exercise

Menu paths below are instructions to locate and verify on the learner's installed version. Screenshots establish their shown windows and controls, not every intervening menu click or the learner's completed work. Use `native-validation.md` for the exact approved view and source bindings.

1. Open the hash-checked working copy with **File → Open**, without a read filter unless documented. In **Statistics → Capture File Properties**, record identity, bounds, precision and the three distinct length measures. `collection-ledger.csv` is authored scenario context; interface, drops, coverage and host schedule remain unknown unless separately evidenced.
2. With the display-filter bar empty, inspect **Statistics → Conversations → TCP**. Record the selected tab, **Limit to display filter**, **Absolute start time**, directional packet/frame-byte counts and observed spans. The cached view has both boxes unchecked and ten conversations. The persistent `192.0.2.10:41000` ↔ `198.51.100.40:80` row has 15 packets/854 frame bytes over 60.0600 seconds. A conversation span is not a count of application requests or a verified connection lifetime. The saved Endpoints view is Ethernet, not IPv4.
3. Select and record UTC or a relative packet-time display; distinguish time reference from timestamp precision and Conversations' separate start-time setting. Apply `tcp.flags.syn == 1 && tcp.flags.ack == 0` to find candidates, then inspect each host/peer/port series and surrounding replies. It includes frame 19, a retry of frame 18, and the unrelated persistent opening at frame 1.
4. For comparable attempt starts, inspect original frames **6/16/20**, **8/14/22** and **10/18/26** separately. Under **Seconds Since Previous Displayed Packet**, display only one accepted series at a time; otherwise subtract its actual UTC/epoch timestamps. Their two intervals are respectively **10/10**, **6/14** and **10/30 seconds**. Exclude same-tuple, same-raw-sequence retry 19. These are attempts, not proved application check-ins, deliberate jitter or a confirmed skipped contact.
5. In **Statistics → I/O Graphs**, record each enabled row's full filter, interval, axis and packet units. Compare one-second and a deliberately selected wider interval, then return to original frames. Raw bin 8 from the first-packet origin contains frames 6/7; bin 21 contains retry 19. A graph counts matching packets, not distinct starts. Separate raw bin arithmetic from the role-limited native GUI evidence in `native-validation.md`. A quiet bin does not prove healthy continuous collection or a pause in the application.
6. Inspect `tcp.stream == 0` separately, and then its `http.request` subset. One visible GET at original frame 4 provides **zero successive application-request intervals**. Zero-payload probe-shaped packets and their replies do not add requests. Return to the full capture and clear all filters when finished.
7. Fill the worksheet before reading the answer key. Test collection limits and ordinary scheduling explanations fairly; distinguish observation from inferred purpose. Then complete the three separate assessments in your own authorized file. If the needed collector-health, schedule or process record is unavailable, leave the corresponding case conclusion unresolved and name the smallest useful next record.
