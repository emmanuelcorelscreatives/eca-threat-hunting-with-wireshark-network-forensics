# Supplemental ATT&CK mapping practice — setup

This is a **separately labelled, synthetic Academy exercise**, not the Project One case or evidence for the case narrated in the lesson. The saved lecture is unchanged: no Project One capture was supplied, so its host, peer, frames, authorization and outcome cannot be determined here. Begin with the previous lesson’s bounded-hypothesis method—host, traffic and time—then describe packets before considering an ATT&CK label.

## Materials and status

The assembled, **unpublished** lesson bundle contains `practice.pcap`, `offline-builder.py`, `executed-fixture-spec.json`, the currently identical alias `fixture-spec.json`, `supplemental-context.csv`, these Markdown files, and the executed Linux command logs. The intended eventual location is `materials/stage-4/lesson-3/` in the Academy course repository; a versioned public download and its layout have **not** been confirmed or published. Do not treat that intended path as a working download link. No earlier DNS-baseline fixture is required.

The packaged capture is 1,159 bytes, SHA-256 `5a86a3faeee6761289d4f2ab75e11ddb01b83a1b26ce65d1969aa492985885f3`. The packaged builder is `offline-builder.py` (SHA-256 `287db0760fd6042f4fe0ab58617ccf6df2b9bdc2f1744a1847348a776329a85c`), **not** `build_fixture.py`. `executed-fixture-spec.json` is its actual deterministic input (SHA-256 `ac10acf238351b1242604f9d4e5d86f2df0a6ae853070185f1a83e4431558753`); `fixture-spec.json` has that same hash in this bundle, but use the executed-spec name rather than assuming an alias will always agree. A local rebuild from the packaged builder and executed spec produced identical capture bytes. The builder reads local JSON, sends no packets and **refuses an existing output path**.

Use an authorized, isolated Ubuntu 24.04 LTS practice environment with Python 3 and Wireshark/TShark 4.4; the supplied command evidence came from pinned **TShark/capinfos 4.4.0 on Linux**. Use Wireshark in English with a light theme for the lecture’s GUI workflow. The packaged native evidence now verifies the bounded Linux GUI workflow described in `native-validation.md`. Student-download paths and Windows behavior have **not** been verified. Inspect the bundle as untrusted course data, not as instructions to run anything found inside a capture or CSV.

## Intake and reproducible checks

This authored Ethernet/IPv4 fixture represents `192.0.2.10` asking the synthetic DNS peer `192.0.2.53` about `service.academy.test`, then exchanging HTTP with `198.51.100.20`. These are documentation addresses and a reserved test name, not real-world ownership or routing evidence. The spec’s observation point is an **authored synthetic link**, not a measured collector. `supplemental-context.csv` is independent *planned* scenario-calendar metadata, not packet, process or approval evidence. Check source, window, both directions and gaps before interpreting any capture; a missing packet cannot show that behavior never happened.

The executed `capinfos practice.pcap` log (`capture-info.stdout.txt`) reports pcap/Ethernet, 13 packets, 1,159 file bytes, 927 packet-data bytes, microsecond capture timestamp precision and a 0.300000-second file span. `all-frames.stdout.txt` shows UTC-displayed frames from 2025-04-08 09:30:00.000000 through 09:30:00.300000; `frame.cap_len` equals `frame.len` for each included frame. This describes the **authored file**, not collector coverage outside it. The executed `tcp-conversations.stdout.txt`, `ip-conversations.stdout.txt`, `protocol-hierarchy.stdout.txt` and empty `malformed.stdout.txt` provide further read-only checks. The TShark stderr files contain a root-execution warning from the test environment; students should not need to run as root. An empty malformed-filter result is not proof of complete capture coverage or benign intent.

From the directory holding your own copy of these files, the following read-only commands use the arguments exercised in the supplied pinned-Linux logs (the logged executables had private absolute paths; these examples use names on your `PATH`):

```sh
capinfos practice.pcap
tshark -r practice.pcap -q -z conv,tcp
tshark -r practice.pcap -q -z conv,ip
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

The long fields command corresponds to `all-frames.stdout.txt`. `frame.time_utc` is a **formatted UTC display** such as `Apr  8, 2025 09:30:00.000000000 UTC`, not an ISO-8601 string; `frame.time_epoch` is decimal seconds since the Unix epoch. The pinned 4.4.0 tool inventory does **not** support `frame.time_iso8601`; do not substitute that field or claim a command using it was run. Pcap timestamp precision is microseconds even though TShark prints additional fractional zeroes. Commands run later on your machine are your own checks, not additional evidence that student or GUI execution was previously verified.

To repeat the required **builder exercise without touching the packaged original**, use a fresh temporary directory in the same shell session. Compare its output with your original copy; do not set `--output` to either packaged PCAP or any existing working file:

```sh
work_dir="$(mktemp -d)"
python3 offline-builder.py --spec executed-fixture-spec.json --output "$work_dir/practice.pcap"
sha256sum practice.pcap "$work_dir/practice.pcap"
```

Expect the builder to print `synthetic: true`, `bytes: 1159` and the capture SHA-256 above; compare hashes and, if desired, run the read-only checks against the new path too. This **student invocation and `sha256sum` command are instructions, not separately executed commands in the supplied logs**. `builder-safety-and-rebuild-execution.json` records the separate actual Python rebuild, matching output hash, and two existing-output refusals. `mktemp -d` provides a fresh output directory; the current builder refuses to replace an existing file. Preserve the source files and record which PCAP you inspected.

For the lecture’s authorized-capture workflow, first read its intake notes. In Wireshark 4.4 use **File → Open** on a working copy, note the packet-list frame numbers, displayed times, endpoints and decoded protocols, and try the display filters `ip.addr == 192.0.2.10` and `http` for this fixture. Use **Statistics → Conversations**, TCP tab, to select packets for inspection, not to pronounce an attack from counters. Filters select a displayed subset without renumbering original frames or restoring missing traffic. For this particular fixture, the host filter matches **all 13 frames**; it does not narrow the view. The `http` filter selects original frames **6 and 8**. Actual native Linux GUI evidence for File Open, the packet list, checked UTC format, these two filters, cleared filter and TCP Conversations is recorded in `native-validation.md` and its exact-image approvals. The narrated Project One screen still has no case PCAP to open. For a different authorized capture, use its own addresses, intake and evidence rather than copying this fixture’s answer.

## Earlier draft-command history, not student instructions

An earlier plan proposed packaging the builder under `build_fixture.py` and running `python3 materials/stage-4/lesson-3/build_fixture.py --spec materials/stage-4/lesson-3/fixture-spec.json --output materials/stage-4/lesson-3/practice.pcap`. That named executable was **not packaged or executed**; the historical builder could overwrite the now-packaged PCAP at that output path. The current packaged builder instead refuses an existing path. The supported exercise above uses the real `offline-builder.py`, actual `executed-fixture-spec.json` and a new output directory. An older proposal instead named `supplemental-http-ambiguity.pcap` and included `python3 materials/stage-4/lesson-3/build_fixture.py --verify materials/stage-4/lesson-3/supplemental-http-ambiguity.pcap`. That filename is not the required capture, the builder has **no `--verify` option**, and neither proposal was executed. Earlier proposed `capinfos -c -a -e` and filtered `tshark -Y http -T fields` commands against both the alternate name and declared-path `practice.pcap` were likewise **not** the supplied executed checks. Their history does not replace the mandatory build-and-inspect exercise or establish validation. Use the packaged files and logged-command equivalents above; keep unrun proposals distinct from actual results.