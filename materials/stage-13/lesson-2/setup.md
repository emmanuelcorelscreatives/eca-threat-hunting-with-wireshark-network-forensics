# Academy supplemental offline timing practice

This kit is **synthetic Academy coursework**, separate from the unchanged Stage 13, Lesson 2 lecture by **EMMANUEL CORELS**. The historical incident capture was not supplied. Its hosts, event times and calculated gaps cannot be transferred to that incident or to a learner's own capture. Work only with an authorized offline source; do not generate or inspect unapproved traffic.

## Source identity, tools and evidence status

The packaged `practice.pcap` is an Ethernet classic PCAP of **1,982 filesystem bytes**, SHA-256 `de49b4bc93e17959c8bfad00ad38b580e358d0e8f4adb8c5c90e375b413b72a0`. `capture-info.stdout.txt` reports **26 captured packets**, **1,542 captured frame bytes**, microsecond timestamp precision, and a **120.140000-second** window from **2025-01-16 12:00:00.000000** to **12:02:00.140000**. The synthetic `scope-card.md` sets client `192.0.2.10`, peer `198.51.100.20`, peer TCP port `80`, and an **authored client-facing link** observation point. The latter is scenario metadata, not evidence of a real sensor or an accurate collection clock.

Use Wireshark on a working copy. Python 3 is needed only for an optional rebuild or checker rerun; the packaged PCAP does not require either to open. The existing `all-frames.stdout.txt` and other decoder logs came from recorded Linux TShark 4.4.0 and `capinfos` runs. `decoded-fields.stdout.csv` adds observed flags, a marked retransmission and checksum-status fields. The independently executed `check_capture.py` parsed PCAP bytes separately from the builder; see `checker-usage.md`, `independent-pcap-execution.json` and `independent-pcap-report.json`. An empty `malformed.stdout.txt` is not that check.

The current `offline-builder.py`, SHA-256 `287db0760fd6042f4fe0ab58617ccf6df2b9bdc2f1744a1847348a776329a85c`, writes an **exclusively created** output file: it refuses existing destinations. `builder-safety-and-rebuild-execution.json` documents an actual fresh output matching the packaged PCAP and refusals for both identical and different pre-existing outputs, with the originals unchanged. The builder constructs offline bytes; it does not transmit packets. `executed-fixture-spec.json`, SHA-256 `82e8296658341a7493f62baa2528231b0fcc68003ea2a844f9babc232418d20e`, is the recorded input. `fixture-plan.json` is an earlier design alias, **not** evidence of an execution naming that file.

`historical-actual-execution-proof.json` retains earlier argv, outputs and older file hashes. It is **not** a current inventory: among other changes, the builder now uses exclusive creation, and its old CSV-header entry is inaccurate. `source-copy-provenance.json` records an earlier copy, not a new command run. The newer safety and checker execution records establish only their stated actions. Neither the historical manifest nor the recipes below establish that a student literally ran them.

## Make a reproducible worksheet record

Keep the original unmodified, open a working copy, and verify which capture supplied every original frame number. The header-only `worksheet.csv` has 16 existing columns, including `source_capture`, `scope_client`, `scope_peer`, `capture_window_utc`, `capture_point`, `original_frame_number`, `timestamp_epoch_seconds`, `candidate_event_type`, `tcp_stream`, `status`, `reason`, `timestamp_rule`, `start_certainty`, `previous_accepted_frame`, `interval_seconds` and `limits`. It has **no hash or peer-port column**. Keep its header unchanged and put these explicit fields in the narrative portion of the submitted worksheet response alongside the CSV:

- **Original capture file and SHA-256:** __________
- **Opened working copy and SHA-256:** __________
- **Scoped client IP:** __________
- **Scoped peer IP:** __________
- **Scoped peer TCP port:** __________
- **Capture window and time zone:** __________
- **Capture point, collection directions and authorization basis:** __________
- **Clock, capture-loss, start-of-window and NAT or translation information, including unknowns:** __________

For this fixture, confirm the scope against `scope-card.md` and packet fields rather than assuming the narrative note itself proves capture coverage. For your own authorized capture, obtain its real scope and collection notes before replacing any blanks. If source addresses changed, resolve the mapping before combining rows; a shared destination alone does not make starts comparable. Record possible exclusions and uncertain starts, not just the rows that produce a tidy interval.

## Perform the native Wireshark workflow

1. In Wireshark choose **File > Open** and select the **working copy**; leave any read filter empty. Confirm the source hash, unfiltered **No.**, Time, Source and Destination columns, capture window, and the scenario scope. `native-00-file-open.png` shows a chooser *before* selection; `native-01-unfiltered.png` shows the opened 26-packet capture. These filenames and their approvals are indexed in `native-independent-approvals.json`. In a real source, document whether the first conversation began before capture, whether a direction or packets might be missing, and whether timestamps from another collector have a checked clock.
2. In the **display-filter bar**, enter `tcp.flags.syn == 1 && tcp.flags.ack == 0` and apply it. This is SYN set, ACK clear: **candidate** client-initiated attempts, not proof of successful connections or requests. The approved native view `native-10-filter-01.png` shows frames **3, 4, 18, 19, 20 and 24** for this fixture. After checking Source, Destination and destination port against the scope card, use this scoped expression:

   ```text
   (tcp.flags.syn == 1 && tcp.flags.ack == 0) && ip.src == 192.0.2.10 && ip.dst == 198.51.100.20 && tcp.dstport == 80
   ```

   The approved scoped-condition view `native-scope-payload-01-scoped-syns.png` shows **3, 4, 20 and 24**. Compare each candidate's directional tuple, TCP flags, stream, raw sequence number and nearby unfiltered packets. Frame **4** repeats frame **3**'s tuple and raw SYN sequence **1000** on stream **1**, 0.400000 seconds later; the native view marks it as a retransmission. Wireshark's default relative sequence display can show **0** instead of raw **1000**. Exclude the retry, not an interval. Frames **18** and **19** are out-of-scope SYNs. Frames **1–2** are ACK-only midstream context with no observed connection start; do not assign frame 1 an invented start time. Later handshake ACKs, responses and closing packets do not start connections. Frame **23** is ACK-only; do not assert it is a proved keep-alive. For this fixture, the reviewed accepted **connection-attempt** frames are **3, 20 and 24** on streams **1, 4 and 5**.
3. For a **separate HTTP-request series**, apply `http.request`, then check and narrow to the same client-to-peer direction and port, for example:

   ```text
   http.request && ip.src == 192.0.2.10 && ip.dst == 198.51.100.20 && tcp.dstport == 80
   ```

   The approved `native-10-filter-02.png` and `native-scope-payload-02-scoped-http-decode.png` show decoded request rows **8 and 12**, not automatically the first-byte frames. Select frame **8**, expand its TCP/reassembly details and inspect the underlying segments. Frame **7** contains the first **17** bytes of `GET /a HTTP/1.1\r\n`; frame **8** supplies the next **25** bytes and completes the **42-byte** header, so Wireshark decodes `/a` on frame 8. `native-scope-payload-frame-7-payload-details.png` and `native-scope-payload-frame-8-payload-details.png` show the respective roles. Frame **12** contains the complete **42-byte** `GET /b` request and is both its first-byte and decoded row, as shown in `native-scope-payload-frame-12-payload-details.png`. Both requests use **stream 1**; they are not two new TCP connections. Under the consistent **first observed request bytes** rule, retain **7 and 12**. If the first portion of a request is absent in another capture, mark its exact start uncertain rather than timestamping a later reassembled row as an exact beginning.
4. Only **after** deciding which starts to retain, apply the exact accepted-only filters below. The approved native views `native-10-filter-03.png` and `native-10-filter-04.png` show these actual frame lists. These fixture frame numbers are **not** reusable filters for a learner's different capture:

   ```text
   frame.number == 3 || frame.number == 20 || frame.number == 24
   ```

   ```text
   frame.number == 7 || frame.number == 12
   ```

   Keep each event type, scoped client and scoped peer in its own time-ordered series. In **View > Time Display Format**, choose **Seconds Since 1970-01-01** (the native Linux 4.4.0 menu label for the lecture's *Seconds Since Epoch*). Read the accepted rows' Time values, retain the UTC capture context, and subtract each previous **accepted same-series** epoch from the next: `Δᵢ = tᵢ − tᵢ₋₁`. For connection frames **3, 20, 24**, the epochs are **1737028800.100000**, **1737028860.100000** and **1737028920.100000**: the gaps are **60.000000 seconds** and **60.000000 seconds**. For request first-byte frames **7, 12**, the epochs are **1737028801.100000** and **1737028821.100000**: the gap is **20.000000 seconds**. The first accepted event in each series has **no previous accepted interval**. Approved menu-state and applied views include `native-accepted-3-epoch-menu.png`, `native-accepted-3-epoch-applied.png`, `native-accepted-4-epoch-menu.png` and `native-accepted-4-epoch-applied.png`. **View > Time Display Format > UTC Date and Time of Day** is also shown in `native-utc-menu.png` and `native-utc-applied.png` for date context. This PCAP has microsecond precision; displayed digits do not calibrate its clock.
5. For an on-screen **cross-check**, keep only the accepted frames for **one** series visible, then choose **View > Time Display Format > Seconds Since Previous Displayed Packet**. Inspect the actual selected radio item, not a hover highlight. With the reviewed connection filter, the approved applied Time column shows **0.000000, 60.000000, 60.000000** in `native-accepted-3-delta-applied.png`. With request first-byte frames 7 and 12, it shows **0.000000, 20.000000** in `native-accepted-4-delta-applied.png`. The first displayed **0.000000** is *not* an interval from an earlier accepted start. The approved menu-state images are `native-accepted-3-delta-menu.png` and `native-accepted-4-delta-menu.png`. Check that the row immediately above every interval is another accepted start of the **same type, client and peer**. **Seconds Since Previous Captured Packet** instead uses the possibly hidden previous captured packet and is not this shortcut. Filtering only `http.request` compares decoded frames **8** and **12** and yields **19.980000 seconds** between those decode rows, not the **20.000000-second first-byte interval**.
6. Inspect time references before trusting a displayed-row gap. The earlier accepted-frame-3 reference test is only a control. The separately executed out-of-filter test selects response frame **10**, sets it as a reference, then applies `frame.number == 3 || frame.number == 20 || frame.number == 24`. Actual visible rows are **3, 10, 20 and 24**, with frame 10 marked `*REF*`; the checked menu remains **Seconds Since Previous Displayed Packet**. Frame 20 displays **58.940000 seconds** from response frame 10, not the **60.000000-second** interval from accepted start 3. After unsetting reference 10 and restoring the same filter, only **3, 20 and 24** remain with displayed values **0.000000, 60.000000 and 60.000000**. The first zero is not a worksheet interval. Exact independently reviewed states are `native-gap-01-response-10-reference-set.png` through `native-gap-04-accepted-after-reference-unset.png`. On another authorized source, record its actual rows and reference state rather than copying these results. If any unaccepted row intervenes, calculate the same-series gap from recorded epochs. Preserve the packet file and unset demonstration references afterward.

Record each accepted or excluded candidate's original unfiltered frame number, source, observed timestamp where useful, event type, `tcp.stream`, status, reason, timestamp rule, certainty and applicable preceding accepted frame. Leave an uncertain **start-time** cell empty even when a later packet has a visible timestamp. Keep retries, out-of-scope SYNs and missing-start context reviewable. The decoded HTTP rows are clues, not automatically connection attempts or exact request starts. The resulting two equal connection gaps describe only this short authored window; **one** request gap cannot show request periodicity. Neither result identifies an endpoint process, service purpose or command and control. Ask for separately authorized endpoint or service context where relevant. If a real source lacks confirmed comparable starts, report **timing unresolved**.

## Optional, safe Linux checks

The following **proposed learner rerun** requires the actual packaged files in the current directory. It machine-checks the **current** builder, actual spec and original PCAP, failing immediately on each mismatch **before invoking the builder**. `mktemp -d` supplies a fresh directory; the current builder refuses an existing output path. Never aim it at the packaged `practice.pcap` or an existing worksheet or report.

```sh
(
  set -eu
  printf '%s  %s\n' '287db0760fd6042f4fe0ab58617ccf6df2b9bdc2f1744a1847348a776329a85c' 'offline-builder.py' | sha256sum -c - || exit 1
  printf '%s  %s\n' '82e8296658341a7493f62baa2528231b0fcc68003ea2a844f9babc232418d20e' 'executed-fixture-spec.json' | sha256sum -c - || exit 1
  printf '%s  %s\n' 'de49b4bc93e17959c8bfad00ad38b580e358d0e8f4adb8c5c90e375b413b72a0' 'practice.pcap' | sha256sum -c - || exit 1
  tmpdir=$(mktemp -d)
  python3 offline-builder.py --spec executed-fixture-spec.json --output "$tmpdir/rebuilt.pcap"
  printf '%s  %s\n' 'de49b4bc93e17959c8bfad00ad38b580e358d0e8f4adb8c5c90e375b413b72a0' "$tmpdir/rebuilt.pcap" | sha256sum -c -
)
```

This example was **not** the recorded historical argv or the actual fresh-rebuild argv in `builder-safety-and-rebuild-execution.json`. A simpler **read-only proposed inspection**, not an additional logged execution, is `tshark -r practice.pcap -T fields -e frame.number -e frame.time_epoch -e tcp.stream -e tcp.seq_raw -e tcp.ack_raw -e tcp.len`. The executed field export is `all-frames.stdout.txt`; its `frame.time_utc` is a human-readable UTC string, not an ISO-8601 field. The pinned-build check found `frame.time_iso8601` unsupported. Refer to `historical-actual-execution-proof.json` for its *actual* old command argv rather than retroactively attributing either proposal to that run. The recorded root warning in some stderr files does not instruct learners to run as root.

## Boundaries and remaining work

`native-independent-approvals.json` indexes exact, independently reviewed **supplemental Linux native PNG states**, not a blanket GUI or main-video approval. `native-05-endpoints.png` is the **default Ethernet** tab, not a selected IPv4 tab. `native-06-io-graphs.png` shows **unfiltered All Packets at 1 second** with packets per second on the vertical axis; its other row's filter is only partly visible. It proves no filtered timing graph, different interval, hidden setting or collection health. `one-second-frame-bin-arithmetic.json` is arithmetic over raw frame records, **not another GUI observation**. `native-03-properties.png` reports a **1,966-byte native Length counter**, distinct from the **1,982-byte filesystem size**; `native-file-accounting.json` explains this build's 16-byte record-header accounting difference, not a truncated capture.

The checker pass does not prove complete collection or authorization. In particular, frame **1**'s ACK is **not established by prior observed reverse bytes**, and stream 0's connection start remains unknown. This TCP/HTTP fixture supplies no DNS resolution, NAT mapping, drop-free coverage, clock calibration, endpoint attribution or remote-instruction finding; `Host: fixture.example` is not DNS evidence. The out-of-filter time-reference GUI test is now recorded in the four `native-gap-*` views and explained in `native-validation.md`. Current guide references have been reconciled. Source-specific evidence for a real learner investigation remains the learner's separate responsibility and is not claimed as supplied. No Windows procedure, public repository placement, versioned download, main visual/render approval or complete final-guide approval is claimed. Each resulting guide requires a separate complete independent review before publication.