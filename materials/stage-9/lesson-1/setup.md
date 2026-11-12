# Setup and resources

**Status:** This assembled kit contains a real, offline-built `practice.pcap`, its packaged `offline-builder.py`, and the builder input `executed-fixture-spec.json`. It has **not** been published at a verified repository path or versioned filename. The capture is labelled synthetic Academy coursework, not the saved lecture’s capture or historical case evidence. Work only with files you have actually received and checked; do not rely on an unverified repository URL.

Keep `practice.pcap`, both supplied JSON specifications, `offline-builder.py`, `collection-notes.md`, `dns-transaction-worksheet.csv`, and the Markdown instructions together in a local kit directory. The supplied command-output logs provide a read-only Linux reference. `dns-fixture-spec.json` is the earlier authored alias with the same modeled events but different file bytes; **`executed-fixture-spec.json` is the input to the attested deterministic rebuild**. Do not replace or edit either specification to make the hashes agree.

The assembled builder is `offline-builder.py` by filename. The earlier command `python3 tools/offline_builder.py --spec materials/stage-09/lesson-01/dns-fixture-spec.json --output materials/stage-09/lesson-01/practice.pcap` described a proposed repository layout; that exact command and layout were **not** verified. The historical builder could overwrite the packaged capture at that path; the current packaged version refuses an existing output. Use a new output directory instead. From a Linux shell with Python 3, Capinfos, TShark and Wireshark installed, substitute the actual directory containing your kit files:

```sh
set -eu
KIT=/absolute/path/to/assembled/lesson-01
test -r "$KIT/offline-builder.py"
test -r "$KIT/executed-fixture-spec.json"
test -r "$KIT/practice.pcap"
printf '%s  %s\n' \
  '287db0760fd6042f4fe0ab58617ccf6df2b9bdc2f1744a1847348a776329a85c' "$KIT/offline-builder.py" \
  '463aa92e1690b351e38582b338f188f1a26951821b5394079f2a77a73cec0c77' "$KIT/executed-fixture-spec.json" \
  '040d42163acaf27081d99a6928d8362f5e7d4ca4a949d3e77522e5742c4e19c6' "$KIT/practice.pcap" \
  | sha256sum --check --strict -
WORK=$(mktemp -d "${TMPDIR:-/tmp}/academy-dns-XXXXXXXX")
python3 "$KIT/offline-builder.py" --spec "$KIT/executed-fixture-spec.json" --output "$WORK/rebuilt-practice.pcap"
printf '%s  %s\n' \
  '040d42163acaf27081d99a6928d8362f5e7d4ca4a949d3e77522e5742c4e19c6' "$WORK/rebuilt-practice.pcap" \
  | sha256sum --check --strict -
cmp "$KIT/practice.pcap" "$WORK/rebuilt-practice.pcap"
CAPTURE="$KIT/practice.pcap"
capinfos "$CAPTURE"
```

The shell block uses `set -eu`: a failed standalone readability test, approved-hash check, rebuild, comparison or tool exits this shell rather than continuing. The three approved source hashes are machine-checked before the builder runs. Run it in an isolated script or subshell if you need to preserve an interactive session. The expected SHA-256 values, respectively, are `287db0760fd6042f4fe0ab58617ccf6df2b9bdc2f1744a1847348a776329a85c`, `463aa92e1690b351e38582b338f188f1a26951821b5394079f2a77a73cec0c77`, and `040d42163acaf27081d99a6928d8362f5e7d4ca4a949d3e77522e5742c4e19c6`; the rebuilt capture should match the last hash and compare identical. **The current builder refuses an existing `--output` path.** Keep its output in the newly created directory, never on top of the supplied PCAP or another original. These are reproducibility instructions, not a claim that these exact shell lines were previously executed.

The recorded Linux execution used the assembled builder and actual spec for an identical deterministic rebuild. It also ran `capinfos practice.pcap`; a TShark 4.4.0 all-frame field export; `-q -z conv,tcp`, `-q -z conv,ip`, and `-q -z io,phs`; and `-Y _ws.malformed`. See the correspondingly named supplied `.stdout.txt` and `.stderr.txt` logs. `capture-info.stdout.txt` reports four Ethernet packets, 428 PCAP file bytes, 340 captured frame bytes, and the expected capture hash. `all-frames.stdout.txt` records `frame.time_epoch` as epoch seconds and `frame.time_utc` as a human-readable UTC display such as `Feb 11, 2025 14:00:00.000000000 UTC`. They are **not** ISO-8601 strings. The pinned build’s tool inventory found `frame.time_iso8601` unsupported; do not use it or describe an old command using it as executed.

For a concise *new* read-only check, the following uses fields present in the recorded export. This shorter command was not itself one of the logged invocations:

```sh
tshark -r "$CAPTURE" -T fields -E header=y -e frame.number -e frame.time_epoch -e frame.time_utc -e frame.len -e frame.cap_len -e frame.protocols -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type -e dns.a
```

This export alone does **not** establish UDP ports, DNS IDs, flags, class, response code, response-frame links, or the Answer section’s owner and TTL. The prior plan’s `test -n "$CAPTURE" && test -r "$CAPTURE" && capinfos -c -a -e "$CAPTURE"` and full `tshark -r "$CAPTURE" -Y 'dns' -T fields ...` question/rcode/answer export remain proposed, not recorded executions; their exact literal proposed forms remain unrun. The newer actual `decoded-fields.stdout.csv` and `dns-details.stdout.txt`, with their execution receipts, now provide DNS-detail inspection; see `native-validation.md`. The earlier `find practice/dns-baseline -maxdepth 2 -type f -print` was likewise a proposed, unrun inventory. `practice/dns-baseline`, described separately as a six-packet fixture, must be inventoried and preserved before it is offered; it is not this four-packet capture or a substitute for it.

Read `collection-notes.md` first. In Wireshark, use **File → Open** on the approved offline PCAP or a documented working copy, record the actual source and collection limits, then apply the `dns` display filter. The filter changes the view, not the saved file. Inspect both DNS pairs and their **Answers** trees as directed in `worksheet.md`; a command-line `dns.a` value is not a substitute for checking the record’s section and owner. The bounded actual native Linux GUI checks and response-frame links are now verified in `native-validation.md`; all Windows behavior remains **unverified** for this kit. The lecture also asks you to try one transaction from your **own authorized capture with its own collection notes**; the synthetic PCAP cannot establish a real workstation, user, application, cache event, or historical case finding. The course repository URL/revision, resource links, any needed versioned aliases, and publication remain to be checked.