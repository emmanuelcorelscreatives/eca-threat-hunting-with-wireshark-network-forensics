# Project 1 — setup and evidence boundaries

## Two different investigations

The **narrated Project 1 case remains unsupplied and unsolved**. Its required investigation is to test one identified workstation’s external session against its actual capture window, asset mapping, and scheduled-activity note. No case capture, case asset list, case note, or case packet references have been supplied. Do not substitute the exercise below for those materials or report a case finding.

The packaged `practice.pcap` is a **separately labelled, wholly synthetic Academy exercise**. Its documentation-only addresses and names are not historical systems. Work offline on an authorized copy; do not capture live traffic or contact the pictured peers. The exercise lets you practice the full comparison—including visible DNS and HTTP exchanges, not just a TCP handshake—while preserving the real case as an implementation hold.

## Files, tools, and release status

The assembled kit contains the binary `practice.pcap`, `offline-builder.py`, `executed-fixture-spec.json`, the current byte-identical alias `fixture-spec.json`, `asset-list.csv`, `scheduled-activity-note.md`, this setup, `worksheet.md`, `answer-guide.md`, and `DATA_DICTIONARY.md`. It also contains the executed `capture-info`, `all-frames`, `ip-conversations`, `tcp-conversations`, `protocol-hierarchy`, and `malformed` `.stdout.txt`/`.stderr.txt` logs. **Assembly is not versioned publication:** Academy must verify and distribute the actual binary and complete download set before advertising a student link. Do not save base64 text as a `.pcap` file.

Use Python 3 for optional rebuilding and Wireshark, TShark, and capinfos for analysis. `offline-builder.py` is the packaged, standard-library-only offline builder; it writes an Ethernet/IPv4 **classic PCAP**, not PCAPNG, and sends no packets. The deterministic builder input actually used was `executed-fixture-spec.json` (SHA-256 `762907fdaa3cbf4a00af603c4649d3cb87124a53135df8fef5cf32ef75b95000`). `fixture-spec.json` has that same hash in this assembly; do not assume an alias in another release is identical without checking. The builder **refuses an existing output path**. Never rebuild over the packaged `practice.pcap` or a working copy.

The assembled capture is 1,883 file bytes, SHA-256 `fe798aee93a40286eebc18e3d683830b695b63b6618a886fe2c7fdb190cdcb15` (`capture-info.stdout.txt`: `File size`, `SHA256`). The builder and specification were packaged, and an actual deterministic rebuild was recorded as byte-identical to that capture. The read-only decoder logs were produced on Linux using pinned TShark/capinfos 4.4.0 binaries. This does **not** verify another installation or Windows behavior. Separate native Linux GUI checks are documented in `native-validation.md`.

### Safe optional rebuild

The following is a **newly supplied Linux-shell recipe, not a claim that these literal commands were logged**. Run it from a directory containing the packaged files. `mktemp -d` selects a new directory; retain the original and compare rather than replacing it:

```sh
rebuild_dir="$(mktemp -d)"
python3 offline-builder.py --spec executed-fixture-spec.json --output "$rebuild_dir/practice.pcap"
sha256sum practice.pcap "$rebuild_dir/practice.pcap"
cmp --silent practice.pcap "$rebuild_dir/practice.pcap" && echo 'byte-identical'
```

Expect the builder to report 1,883 bytes and the capture hash above if the inputs match this assembly. A failed comparison requires investigation; it is not permission to overwrite the original. On another platform choose a genuinely **new, empty output directory** and suitable comparison tools; no Windows command sequence has been verified.

Historical draft commands used `offline_builder.py --spec fixture-spec.json --output practice.pcap`, a fixed `/tmp/practice-rebuild.pcap`, and `cmp --silent practice.pcap /tmp/practice-rebuild.pcap`. The underscored builder name is **not** the packaged filename, the executed specification is `executed-fixture-spec.json`, and either fixed output could overwrite an existing file under the historical builder. The current packaged builder instead refuses existing output paths. Those literal draft commands were not the recorded execution. An earlier proposed Scapy generator and PCAPNG filenames were likewise proposals, not packaged alternatives and not replacements for the missing narrated-case materials. The proposed repository location `materials/stage-4/lesson-5/project-1-supplemental/` in `https://github.com/emmanuelcorelscreatives/eca-threat-hunting-with-wireshark-network-forensics` is historical planning, **not a verified published download**.

## Recorded read-only checks and a reproducible field export

The supplied Linux logs record successful `capinfos practice.pcap` and the TShark argument sequences below, run with the pinned binaries. Substitute your installed executable names only to **repeat** the checks; a repeat on another build is not the already-executed check. Read `capture-info.stdout.txt`, `all-frames.stdout.txt`, and the other named logs for the recorded output. The TShark stderr logs contain a warning about running as root; students should not run as root.

```sh
capinfos practice.pcap
tshark -r practice.pcap -q -z conv,ip
tshark -r practice.pcap -q -z conv,tcp
tshark -r practice.pcap -q -z io,phs
tshark -r practice.pcap -Y _ws.malformed -T fields -e frame.number
tshark -r practice.pcap -T fields -E header=y \
  -e frame.number -e frame.time_epoch -e frame.time_utc \
  -e frame.len -e frame.cap_len -e frame.protocols \
  -e ip.src -e ip.dst -e tcp.stream -e tcp.srcport -e tcp.dstport \
  -e tcp.seq_raw -e tcp.ack_raw -e tcp.len -e tcp.payload \
  -e dns.qry.name -e dns.qry.type -e dns.a \
  -e http.request.method -e http.request.uri -e http.host \
  -e http.response.code -e http.file_data
```

The final command lists the fields of the **executed** `all-frames` export. `frame.time_utc` yields human-readable strings such as `Jan 16, 2025 12:02:15.060000000 UTC`; `frame.time_epoch` yields numeric Unix seconds such as `1737028935.060000000`. Neither is an ISO-8601-formatted field. The pinned 4.4 build’s tool inventory reports `frame.time_iso8601` **unsupported**: do not copy an earlier draft export using it or claim that invalid export ran. The earlier proposed `capinfos -c -a -e practice.pcap` and literal unqualified-shell commands were not separately recorded; the supplied capinfos log is from `capinfos practice.pcap`. The IPv4-conversations analysis *was* recorded with `-q -z conv,ip`, using the pinned executable. The old fixed-path rebuild and `cmp` command were not the recorded deterministic-rebuild procedure.

Recorded results (`capture-info.stdout.txt`) are 22 packets, earliest `2025-01-16 12:01:00.000000`, latest `2025-01-16 12:02:15.160000`, 75.160000 seconds’ span, 1,507 **captured frame-data bytes**, Ethernet encapsulation, microsecond timestamp precision, and one file interface. `frame.time_utc` in `all-frames.stdout.txt` supplies the explicit UTC interpretation of the boundary packets. The PCAP header and those timestamps do **not** establish an accurate collector clock, measured collector placement, complete network-path coverage, or richer PCAPNG collection metadata. The empty `malformed.stdout.txt` means this filter reported no frames on that build; checksums were not independently tested by the supplied field export.

## Work from the whole file, then narrow

Preserve the distributed original, make and record an authorized working copy, and disclose any sanitization before sharing frame numbers. For the **real case, only when its materials arrive**, obtain its actual workstation identifier, time-valid address mapping, activity note, capture, clock reference, and observation-point information. Do not carry the synthetic addresses or times over to it.

In Wireshark, use **File → Open** to select the verified working copy rather than a live interface. Before filtering, inspect the full packet view and **Statistics → Capture File Properties** for first/last packet times and whatever collection details the file actually reports. Check the viewer’s time display against the note’s UTC reference; a displayed precise time cannot repair an unknown clock offset. In **Statistics → Conversations**, check its display-filter setting, clear an earlier limiting filter when comparing the whole capture, and use endpoint pairs, starts, durations, counts, and directions to *locate* a candidate—not infer its purpose. The executed CLI conversation logs explicitly say `Filter:<No Filter>`; separate exact native Linux GUI checks are now listed in `native-validation.md`.

For this fixture, the asset list maps WKS-17 to `192.0.2.10` during the capture. A starting display filter is `ip.addr == 192.0.2.10`; `ip.addr` matches either IPv4 direction. Inspect the scheduled peer and the other peer, their DNS and visible HTTP packets, and nearby traffic; record source-file frame numbers and decoded fields. Then **clear the display filter**. A filter hides packets; it does not delete them. A TCP handshake alone cannot answer what was visibly exchanged or who initiated it as a process. For a real case, replace the address only after verifying its owner during that window. If the candidate, ownership, or necessary part of an exchange lies outside observed coverage, stop and record the limitation rather than treating missing packets as negative evidence.

These bounded Linux GUI steps were tested on the supplied synthetic practice capture as documented in `native-validation.md`; no Windows testing is claimed. The historical case and any requirement for independently verified clock or network-path coverage, process attribution, additional protocols, or PCAPNG collection metadata remain unmet by this synthetic PCAP.