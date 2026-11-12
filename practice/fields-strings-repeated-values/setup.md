# Work with Fields, Strings and Repeated Values

This is newly authored, synthetic Emmanuel Corels Academy coursework for Stage 5, Lesson 3. It is separate from the unavailable capture discussed in the unchanged lecture. It contains no historical incident evidence. Work offline with the supplied file or your own authorized working copy; do not start live collection.

## Open and identify the fixture

Open `practice.pcap` with Wireshark File → Open and leave the read filter empty. Verify SHA-256 `55faee8257fa47860f905c5b5f59d37dd04eb75cbf60f7ce0150dd6162b8db23`. The file has 20 Ethernet/IPv4 frames, 1,697 file bytes and 1,353 frame bytes. Microsecond capture precision is distinct from the number of displayed decimal places. Clear the display filter before establishing reference packets. Use Wireshark/TShark 4.4.0 for direct comparison with the supplied records; different versions or analysis settings must be recorded and checked rather than assumed identical.

The actual 14 expressions and the composite in `worksheet.md` were run on pinned Ubuntu Linux TShark 4.4.0 and official Windows TShark 4.4.0. Their exact ordered frame selections agree. `measured-filter-results.json` identifies the separate Linux/Windows stdout and stderr files. The 18 Windows GUI filter/open/clear views also passed independent pixel review against these selections; `windows-current-gui-execution.json`, `windows-gui-*.png` and `windows-independent-gui-batch-*.json` retain the evidence. A green expression proves accepted syntax, not investigative relevance. Learners still predict, apply, inspect both displayed and hidden reference packets, and record their own observations.

## Native packet details and timestamps

`linux-command-16.stdout.txt` directly exports repeated `tcp.port` occurrences and per-packet `tcp.flags.syn`. Native Windows packet detail text for frames 3, 6 and 20 is supplied as `windows-frame-N-native-details.txt`, alongside screenshots. Copied expanded text can contain more rows than fit one viewport. Read the per-packet TCP Flags/Syn bit; a TCP conversation-completeness label “SYN: Present” is a different fact. Actual time-menu records use a byte-identical, uniquely named `fields-practice.pcap` alias for validation. The learner file remains `practice.pcap`.

`frame.time_epoch` is decimal epoch seconds. `frame.time_utc` is human-readable UTC text, not ISO 8601. This build does not support `frame.time_iso8601`. Preserve original timestamps and their time basis. Local Date and Time of Day uses the workstation timezone; record it or explicitly choose the native UTC display. Do not infer an event's clock accuracy from display formatting. Raw `tcp.seq_raw`/`tcp.ack_raw` differ from a GUI's optional relative sequence display.

## Independently reproduce without overwriting

Python 3 and the packaged standard-library builder are sufficient; no pip packages, network connection or capture privileges are needed. The exact consumed input is `executed-fixture-spec.json`. `synthetic-fields-repeated-values.json` is a historical authored alias, not the recorded rebuild input.

```sh
OUT=$(mktemp -d)
python3 offline-builder.py --spec executed-fixture-spec.json --output "$OUT/practice.pcap"
sha256sum "$OUT/practice.pcap"
capinfos "$OUT/practice.pcap"
```

The builder now exclusively creates its output. It refuses an existing path. `builder-current-verification.json` records a fresh byte-identical rebuild and an unchanged output after the expected refused overwrite; its stderr is retained. The shell recipe is a learner reproduction route, not a claim that every line of that exact shell block was run during validation. `verification-only-rebuilt.pcap` is the recorded duplicate, not a second source capture.

## Authored and decoded records

`packet-manifest.csv` retains its authored roles and blank `observed_frame` cells. `decoded-frames.csv` is the independently executed field export. `decoded-frame-join-proof.json` checks all 20 ordered events against decoded frame numbers, exact timestamps, addresses, ports, methods/URIs and SYN values. This mapping relies on this controlled builder's one-frame-per-event order and corroborating fields; it is not a general join rule for unrelated captures. Do not silently fill the learner observation cells.

`current-kit-inventory.json` hashes the delivered files after these guide updates. `historical-assembly-execution-proof.json` preserves the earlier assembly snapshot and earlier prose hashes; it does not describe current guide content. Earlier draft Scapy/PCAPNG filenames or an unimplemented `--check` interface are superseded by the complete packaged PCAP, consumed spec, safe builder, decoded CSV and checked mapping. The actual learner exercise is retained, rather than depending on those obsolete duplicate draft names.

Read `worksheet.md` before `answer-guide.md`. This file contains DNS and plaintext HTTP requests plus TCP handshakes; it contains no HTTP response body, downloaded CSV/PDF content or decoded TLS session. Port 443 does not change those limits. Source case findings, maliciousness and user intent remain unsupported. The candidate repository directory is `practice/fields-strings-repeated-values/` in `https://github.com/emmanuelcorelscreatives/eca-threat-hunting-with-wireshark-network-forensics`; this delivery still awaits separate whole-kit approval and publication, so no new public commit or live download is claimed.
