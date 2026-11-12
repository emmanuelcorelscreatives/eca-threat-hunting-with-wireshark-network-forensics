# Setup — synthetic TCP reassembly and Decode As practice

## Scope and files

Work offline with the **packaged** `practice.pcap`. This authored Academy coursework is separate from the saved Wireshark 4.4, Windows 11 walkthrough, whose packet list was empty because no lesson-case capture was supplied. Do not turn a fixture observation into a historical case finding. No live capture, credentials, network access, or installation of the builder is needed merely to open the PCAP.

The local assembly includes `offline-builder.py` (SHA-256 `2e3f5f0f28b7f44cc7f0a84f8fec600ed2298db85a683619cb835c6be44ae98e`), its **actual executed input** `executed-fixture-spec.json` (SHA-256 `06f18bd4e82101cbd07fa55fbea92052d98e75bb7a6e26233fb458a93e864196`), and `practice.pcap` (1,964 bytes; SHA-256 `e3c4b9f4f6be6e69a2c6fda82e2d33bf94c61816c7d3e8c14695304b58e99b54`). `fixture.json` is the earlier, differently formatted spec alias; it was **not** the input named in the deterministic execution record. Use the executed spec to reproduce that record. The packaged `capture-info.stdout.txt`, `all-frames.stdout.txt`, `tcp-conversations.stdout.txt`, `ip-conversations.stdout.txt`, `protocol-hierarchy.stdout.txt`, and `malformed.stdout.txt` are the supplied read-only Linux results; accompanying stderr files record the root-user warning where present.

The proposed repository path remains `practice/reassembly-decode-as/` under `https://github.com/emmanuelcorelscreatives/eca-threat-hunting-with-wireshark-network-forensics`. Its versioned layout and downloads have not been verified or published. In particular, `synthetic-tcp-http-18081.pcap` was a proposed **same-capture download alias**, not an additional packaged capture. Do not offer that filename as a download until a byte-identical copy is actually published and checked.

## Safely reproduce the build, if needed

The builder is offline and writes Ethernet/IPv4/TCP PCAP bytes; it **overwrites its output path**. Preserve the packaged `practice.pcap` and all originals. From a directory containing the packaged builder and executed spec, choose a genuinely **new, previously unused** directory/path, for example:

```sh
python3 offline-builder.py --spec executed-fixture-spec.json --output ./new-unique-reassembly-run/practice.pcap
```

The builder creates the output directory. Do not reuse that example directory if it already contains a file. The supplied deterministic rebuild, using the packaged builder and executed spec, printed `{"synthetic": true, "bytes": 1964, "sha256": "e3c4b9f4f6be6e69a2c6fda82e2d33bf94c61816c7d3e8c14695304b58e99b54"}` and matched the packaged capture. The example command above is an instruction for a **new** path, not a claim that this exact path was executed. Python 3 is needed only to rebuild, not to inspect the packaged PCAP.

The older draft proposed `py -3 offline_builder.py --spec fixture.json --output practice.pcap`. Preserve that history, but **do not run it as written**: `offline_builder.py` is not the packaged filename, `fixture.json` was not the executed input, the Windows invocation has not been tested, and its output path would overwrite the original. A proposed Windows adaptation is `py -3 offline-builder.py --spec executed-fixture-spec.json --output ./new-unique-reassembly-run/practice.pcap`, after checking that the chosen destination does not exist; it too is **unverified**. The earlier proposed `--check` option is not implemented by this builder. An earlier proposed `frame.time_iso8601` field is unsupported by the pinned 4.4 tool inventory; no command using that field is an executed result.

## Read-only command evidence and optional repetition

The supplied logs came from Linux TShark **4.4.0** and `capinfos`, with `practice.pcap` as input. The recorded commands used the pinned binaries' absolute paths; these short executable names assume the same version is on your `PATH`. The arguments below reproduce the executed **baseline, without a Decode As override**. The shorthand invocations and any Windows adaptation have not separately been run:

```sh
capinfos practice.pcap
tshark -r practice.pcap -T fields -E header=y -e frame.number -e frame.time_epoch -e frame.time_utc -e frame.len -e frame.cap_len -e frame.protocols -e ip.src -e ip.dst -e tcp.stream -e tcp.srcport -e tcp.dstport -e tcp.seq_raw -e tcp.ack_raw -e tcp.len -e tcp.payload -e dns.qry.name -e dns.qry.type -e dns.a -e http.request.method -e http.request.uri -e http.host -e http.response.code -e http.file_data
tshark -r practice.pcap -q -z conv,tcp
tshark -r practice.pcap -q -z conv,ip
tshark -r practice.pcap -q -z io,phs
tshark -r practice.pcap -Y _ws.malformed -T fields -e frame.number
```

The actual baseline output is in the correspondingly named logs. `frame.time_epoch` is epoch seconds printed with fractional digits; `frame.time_utc` prints strings such as `Jan 16, 2025 12:00:00.030000000 UTC`, **not** ISO-8601. `capinfos` reports microsecond PCAP timestamp precision; printed nanosecond-width digits do not create finer capture precision. `frame.len` and `frame.cap_len` describe frames, while `tcp.len` describes TCP payload; none is the PCAP file size or proof of real-world collection coverage. The empty malformed-filter output does not verify every checksum or prove that no traffic was missed.

The old draft also proposed Windows PowerShell TShark field extraction and `-d 'tcp.port==18081,http'` extraction. **Neither Windows command nor any explicit `-d` comparison ran.** For a follow-up read-only *proposal* on an installed 4.4.0 TShark, retain the original file and compare the baseline with:

```sh
tshark -r practice.pcap -d 'tcp.port==18081,http' -T fields -E header=y -e frame.number -e tcp.stream -e tcp.segment -e tcp.reassembled_in -e http.request.method -e http.request.uri -e http.host -e http.response.code -e http.file_data
```

Record the actual output or an error; do not copy expected link or method values into an answer. This proposed command is **not** in the executed logs. It tests a port-wide reading in that invocation; it does not document a Windows GUI Decode As entry. The supplied baseline already labels frames 6 and 11 HTTP, so an override is not guaranteed to make HTTP first appear.

## Learner GUI procedure — required, not yet independently checked

Use an authorized offline working copy in Wireshark 4.4; the saved lecture specifies Windows 11, English, light theme. The steps below follow that lecture, **not** an executed GUI test. First record the authored UTC window, synthetic observation point, and coverage limits from `DATA_DICTIONARY.md`. Find both conversations and inspect both directions before narrowing the intended exchange with its observed `tcp.stream` identifier (`tcp.stream == 0` in the supplied Linux baseline). A display filter hides packets; it cannot recover missing ones. Use `tcp.len > 0` to locate payload-bearing packets, then restore the broader conversation view for timing and acknowledgments.

Inspect raw Packet Bytes and each contributing packet. Where the dissector exposes them, record `tcp.segment` and `tcp.reassembled_in` links and any separate reassembled Packet Bytes tab; do **not** invent links if absent. Check the TCP preference **Allow subdissector to reassemble TCP streams** (described as enabled by default in the lecture) and any application reassembly preference, recording changes. Preferences cannot replace uncaptured bytes. Use **Analyze → Follow → TCP Stream** to compare both directions in text or hexadecimal, then return to the packet list for order and timing. Per the lecture, **Back** restores the prior filter and **Close** keeps the stream filter; the actual GUI behavior remains to be checked on the target installation.

Only after examining request **and** response bytes, consider **Analyze → Decode As** or a real packet's context menu. Record **Field, Value, and Current dissector before applying**, including whether the selected field can be overridden and whether it affects the other conversation on port 18081. Test HTTP tentatively; **OK** applies a session entry, **Save** is unnecessary, and the minus control removes the selected entry. Compare both directions, the independent same-port exchange, raw bytes, message boundaries and decoded fields; then remove the entry and record the original view. A changed protocol label is an interpretation, not new evidence. If no meaningful request fields or reassembly links appear, report that gap rather than declaring a successful full HTTP decode.

No Windows command, GUI preference, Follow Stream behavior, Decode As Field/Value selection, explicit override result, or packet-level reassembly link has been verified by the supplied execution. Those checks and versioned publication remain holds.