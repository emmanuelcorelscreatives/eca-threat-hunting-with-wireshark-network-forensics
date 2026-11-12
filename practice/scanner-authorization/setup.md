# Supplemental synthetic case: scanner authorization

This is labelled, offline Academy coursework, **not** a capture of the narrated historical case or evidence that any real scan was authorized or adversarial. The lesson's objective remains to compare packet behavior with the approved task that actually ran, its scope, ownership, and competing explanations. No live scan, credentials, or production data are needed. Use only an authorized offline capture. The intended GUI environment is Wireshark 4.4.0 on Ubuntu 24.04 LTS; The bounded Linux GUI workflow is now verified in `native-validation.md`; all Windows behavior remains **unverified**.

## What is packaged

Keep `practice.pcap`, `executed-fixture-spec.json`, `offline-builder.py`, the four CSVs, the four core guides (`setup.md`, `worksheet.md`, `answer-guide.md`, `DATA_DICTIONARY.md`), and the additional `README.md` and `native-validation.md` together. The supplied read-only Linux results are `capture-info.stdout.txt`, `all-frames.stdout.txt`, `ip-conversations.stdout.txt`, `tcp-conversations.stdout.txt`, `protocol-hierarchy.stdout.txt`, and `malformed.stdout.txt`, with corresponding stderr logs. The logged TShark invocations used a pinned 4.4.0 Linux binary. Their stderr warning about running as root is not a packet finding; do your own work unprivileged.

`executed-fixture-spec.json` is the **actual builder input**, not the earlier proposed `fixture.json` or `fixtureSpec` alias. `offline-builder.py` is the **packaged executable**, not the proposed `offline_builder.py`. The packaged capture is already usable; rebuilding is optional. The recorded deterministic rebuild of these actual inputs produced the same 1,074-byte PCAP with SHA-256 `32ae0b96d7e4f8740380b3693baf26cbeea8673118e2e1801a1255fa5f791c7f`. The builder sends no packets, but **refuses an existing output path**. Preserve the packaged capture and logs: for an optional Linux rebuild, run the following *local recipe* in the kit directory and use a newly created temporary output directory. These literal shell invocations are proposed student steps, not additional executed-log results.

```sh
python3 -m json.tool executed-fixture-spec.json > /dev/null
workdir=$(mktemp -d)
python3 offline-builder.py --spec executed-fixture-spec.json --output "$workdir/practice.pcap"
sha256sum "$workdir/practice.pcap"
```

Do not point `--output` at the supplied `practice.pcap`, an existing student's file, or the source directory. Check the printed hash against the recorded value; if it differs, investigate rather than changing the fixture. On another platform, arrange a **new empty output location** before invoking the builder; no Windows command has been tested. Open either the preserved supplied PCAP or your separately rebuilt copy locally.

## Established by supplied read-only logs, not by GUI review

`capture-info.stdout.txt` identifies Ethernet **PCAP**, microsecond timestamp precision, 15 packets, 1,074 file bytes, 810 captured packet bytes, and a 121-second span. `all-frames.stdout.txt` gives the first and last frames as **2025-01-16 10:05:00.100–10:07:01.100 UTC** through `frame.time_utc`; its `frame.time_epoch` values are UTC Unix seconds. `frame.time_utc` is a human-readable UTC string, **not ISO 8601**. The pinned 4.4 build's tool inventory does not support `frame.time_iso8601`; do not use that field or claim an earlier invalid command ran. `capture-info.stdout.txt` omits a zone suffix on its earliest/latest display, so use the explicitly UTC frame field and the UTC fixture timestamps when reporting bounds.

`protocol-hierarchy.stdout.txt` reports 15 Ethernet/IPv4/TCP frames and 810 frame bytes. Every row of `all-frames.stdout.txt` has `frame.len=frame.cap_len=54`, `tcp.len=0`, and empty TCP payload, DNS, and HTTP fields. There is no visible UDP, DNS, ICMP, HTTP, application request, vulnerability-check content, or transferred file content in this fixture. A TCP handshake is not proof of a completed vulnerability scan, application session, operator, or host process. `malformed.stdout.txt` is empty for the executed `_ws.malformed` filter; that does not establish path coverage. The two logged Conversations outputs have `Filter:<No Filter>` and six IPv4/TCP pairs. Their byte counts are captured **frame** bytes, not TCP payload or file-content bytes.

The actual read-only Linux invocations include `capinfos practice.pcap`, TShark with `-r practice.pcap -q -z conv,ip`, `-z conv,tcp`, and `-z io,phs`, an all-frames fields export, and `-Y _ws.malformed -T fields -e frame.number`; the supplied stdout files are the results. They used absolute pinned executable paths. The following shorter commands are **proposed local checks**, not claims that these exact PATH-based or new-path invocations ran in the supplied logs. The original all-frames export did **not** include `tcp.flags`; the separately executed `decoded-fields.stdout.csv` now includes actual flags and raw fields. `syn-filter.execution.json` retains the actual exact SYN-filter result. These newer checks do not retroactively change the old log or claim these literal student commands ran.

```sh
capinfos "$workdir/practice.pcap"
tshark -r "$workdir/practice.pcap" -q -z conv,ip
tshark -r "$workdir/practice.pcap" -q -z conv,tcp
tshark -r "$workdir/practice.pcap" -q -z io,phs
tshark -r "$workdir/practice.pcap" -T fields -E header=y -e frame.number -e frame.time_utc -e frame.time_epoch -e frame.len -e frame.cap_len -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags -e tcp.seq_raw -e tcp.ack_raw -e tcp.len
tshark -r "$workdir/practice.pcap" -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e frame.number -e frame.time_utc -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.seq_raw
```

If you skip rebuilding, substitute the supplied `practice.pcap` for the temporary path. `tcp.seq_raw` is the raw on-wire sequence field exported in the executed log; `tcp.seq` or a Wireshark relative-sequence display can show a different number. The actual newer `decoded-fields.stdout.csv` marks frames4 and15 with `tcp.analysis.retransmission=1`; retain the independent tuple, raw-sequence, timing and reply checks rather than treating that analyzer mark alone as proof of a distinct target, authorization or process.

## Manual Wireshark investigation still required

Open the offline file, establish and record the displayed time zone (use UTC for comparison), and inspect capture properties and packets for limits. The fixture describes **one authored synthetic Ethernet link**; `capinfos`' logical interface #0 is not a physical tap location, routing map, or labelled pcapng interface. The actual collection path and traffic elsewhere are unknown. Compare the visible bounds with each CSV window; silence before, after, or off this link cannot exclude traffic.

In Statistics → Endpoints, compare the broad view with any display-filter-limited view; determine who initiated from packet direction, not an endpoint listing. In Statistics → Conversations, examine contacts, starts, durations, frame counts, and frame bytes; the supplied unfiltered CLI tables and separately checked native views in `native-validation.md` are distinct evidence. In Statistics → I/O Graphs, compare the 10:05 scanner, 10:06 administrator, and 10:07 single-peer periods using the same proposed **one-second** interval; the actual graph interval, filters and results are now documented in `native-validation.md`. Apply `tcp.flags.syn == 1 && tcp.flags.ack == 0`, inspect each match and both directions of its exchange, and test same-tuple retries. Clear or adjust the filter and check whether it limits Conversations before saying a peer was not visible. Cite inspected frame numbers, not fixture event positions. Check inventory mappings, approval, *actual* job execution and configured scope, and tickets separately from packet observations; request owner, process, and service confirmation where missing.

## Earlier proposals and implementation holds

Earlier prose proposed `python3 -m json.tool fixture.json`, `python3 offline_builder.py --spec fixture.json --output practice.pcap`, `tshark --version`, a combined `-z endpoints,ip -z conv,tcp` check, a SYN export using `tcp.seq`/`tcp.analysis.retransmission`, and an interface/ICMP fields export. Those **literal commands are not among the supplied executed logs**; their proposed input filenames also differ from the packaged ones. In particular, an interface-ID field would not establish a physical path, and this capture has no ICMP packets. Do not present those proposals as completed checks.

The separate earlier versioned case-pack plan named `practice/scanner-authorization/fixture.json`, `scripts/build_case.py --spec … --output-dir …`, `scripts/verify_case.py --spec … --data-dir …`, `data/discovery-comparison.pcapng` with labelled interface metadata, and `data/capture-context.json` with defensible observation-point and coverage context. None is delivered or verified by this PCAP builder. It accepts `--output`, not `--output-dir`; **do not rename PCAP to pcapng**. If those materials or further protocol/application evidence are mandatory for the planned case pack, implement and independently check them rather than treating TCP-only coursework as a substitute. Physical network-path coverage, real task/host confirmation, repository and publication paths, and versioned publication remain outstanding. The bounded Ubuntu GUI review is now documented separately in `native-validation.md`.