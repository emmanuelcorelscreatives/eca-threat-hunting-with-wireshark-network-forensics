# Interpret retransmissions and Expert Information

This is a new Academy-authored, offline synthetic exercise for Stage 6, Lesson 2. It supplements the saved lecture and is not a capture of its hypothetical incident. No live packets were sent. The capture encodes observations, not an actual receiver state or network failure.

Open `synthetic-tcp-evidence.pcapng` in your installed Wireshark. This complete supplied fixture has 17 records on two named synthetic interfaces in a 0.2 second interval. `practice.pcap` is the distinct original 16-record single-interface fixture; its frame numbers differ after frame 4. Use the PCAPNG for every worksheet answer. Neither interface name describes a real collection point.

Start with Capture File Properties. Record your version, start/end times, duration and saved interface details. Then open Analyze → Expert Information (the label may be Expert Info in other versions). Check whether the dialog is limited to the current display filter. The supplied verification used native TShark and capinfos 4.4.0 on Linux. An independently reviewed native Linux Expert Information image is included with “Limit to Display Filter” checked for `tcp.stream == 0`. Additional actual Properties/filter captures are retained in the production evidence, with no independent approval claimed. The worksheet asks you to perform the complete investigation in your installed version.

## Rebuild and verify

Python 3 standard library is sufficient. `requirements.txt` intentionally has no third-party dependencies. From this directory, use an isolated virtual environment if you want to run the dependency check:

```sh
python3 -m venv /tmp/stage6l2-venv
/tmp/stage6l2-venv/bin/python -m pip install -r requirements.txt
python3 generate_fixture.py --output /tmp/stage6l2-rebuilt.pcapng
sha256sum synthetic-tcp-evidence.pcapng /tmp/stage6l2-rebuilt.pcapng
capinfos -c -u -a -e -I synthetic-tcp-evidence.pcapng
tshark -n -r synthetic-tcp-evidence.pcapng -q -z conv,tcp
tshark -n -r synthetic-tcp-evidence.pcapng -Y 'tcp.analysis.retransmission || tcp.analysis.lost_segment || tcp.analysis.duplicate_ack || tcp.analysis.out_of_order || tcp.analysis.fast_retransmission || tcp.flags.reset == 1' -T fields -e frame.number -e frame.interface_id -e tcp.stream -e tcp.seq_raw -e tcp.ack_raw -e tcp.len
```

Choose a new output path: the PCAPNG generator refuses to overwrite an existing file. The original `offline-builder.py` overwrites its output, so always give it a new output path and preserve the supplied evidence. `generate_fixture.py` verifies the original PCAP hash before building the PCAPNG. `offline-builder.py` and `executed-fixture-spec.json` reproduce only the original PCAP; use its `--spec` and `--output` options. The separate `synthetic-tcp-evidence.spec.json` is the original authored design, not the multi-interface packet decoder output.

The Academy public directory is `materials/stage-6/lesson-2/` in [the course repository](https://github.com/emmanuelcorelscreatives/eca-threat-hunting-with-wireshark-network-forensics). `README.md`, `evidence-worksheet.md` and `instructor-key.md` are exact publication aliases of setup, worksheet and answer guide respectively. The offline ZIP includes the captures, generators, inputs and actual command receipts. Original `all-frames`, capture-info, protocol hierarchy and IP/TCP conversations receipts refer to the 16-frame PCAP. New `fields`, `properties`, `conversations`, `expert`, `malformed` and per-filter receipts refer to the 17-frame PCAPNG; use `execution.json` for exact arguments.
