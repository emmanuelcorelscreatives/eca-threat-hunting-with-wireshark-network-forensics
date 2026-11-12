# Setup and complete workflow

Use the supplied practice.pcap offline with Wireshark 4.4.0. No live capture, credentials or network traffic is required. The capture is explicitly authored synthetic Academy coursework:26 frames on an artificial Ethernet link, two TCP conversations sharing server port 18081, with segmented request/response bytes and a different same-port control. The historical case remains unavailable.

## Reproduce safely

Python 3 is needed only to rebuild. Preserve original files and choose a NEW unused output directory:

```sh
python3 offline-builder.py --spec executed-fixture-spec.json --output ./new-unique-reassembly-run/practice.pcap
```

The builder overwrites its destination; never point it at the packaged PCAP. Its actual deterministic rebuild is retained in history/actual-execution-proof.json and matches the SHA-256 in README.md. fixture.json is an earlier differently formatted alias; executed-fixture-spec.json is the executed input. The older offline_builder.py filename and --check option were proposals; they are not implemented interfaces. No Windows Python command was executed.

## Establish scope in Wireshark

Open practice.pcap. Confirm 26 packets, restore an empty display filter, and inspect both conversations using tcp.stream == 0 and tcp.stream == 1. Record the entire conversation before narrowing with tcp.len > 0. Frame time and raw sequence tables are in all-frames.stdout.txt; raw values differ from default relative sequence display. Record collection limits and distinguish the artificial timestamp window from real capture coverage.

Select a stream 0 packet and choose Analyze → Follow → TCP Stream. Inspect both directions together and separately in ASCII or hexadecimal. A tested native both-direction view contains 95 TCP bytes; native/v2-02-follow-both.png shows reconstructed request and response. Click Back to restore the previous filter; native/v7-03-back-restores-ip-filter.png records the restored prior IP-address filter. Close leaves the follow filter; record your own actual state and restore the prior filter manually if needed. The reference captures did not separately test every direction-selector or Close permutation.

Inspect original frames 4–6 and 8–11, their timing, lengths, sequence progression and both Packet Bytes and packet details. Edit → Preferences → Protocols → TCP shows Allow subdissector to reassemble TCP streams checked and Reassemble out-of-order segments unchecked in native/v5-08-tcp-preferences.png. These are the checked reference profile settings; do not change unrelated preferences. Check application reassembly settings if required by your own installation; no HTTP preference toggle is claimed by these screenshots.

## Reversible Decode As test

First record baseline interpretation and request fields. Only after the captured bytes support HTTP, use Analyze → Decode As. Add TCP port, enter 18081, and choose HTTP; inspect Field, Value and Current carefully before applying. Do not accept the source port 54010 offered for a selected client packet when the intended test is server port 18081. The reference explicit 18081 override was supplied at application startup with -d tcp.port==18081,http, then inspected and removed through the real GUI. It is not evidence that a user manually typed the entry in the dialog. native/v5-01-current-port18081.png shows TCP port 18081/HTTP. Compare stream 0 request and response fields, contributing segments and Reassembled TCP Packet Bytes tabs. native/v5-02-request-reassembly.png and native/v5-03-response-reassembly.png provide checked reference views.

Inspect tcp.stream == 1 under the SAME port-wide override. Its NOTE payloads are a control, not HTTP merely because a dissector is selected. Remove the selected override with the minus control and OK; native/v5-05-before-remove.png and native/v5-06-removed.png record the entry and empty table. Clear the display filter; native/v5-07-restored.png shows the 26 frame packet view. Do not Save the override persistently for this exercise. Restore any preferences you changed.

## Executed CLI comparison

TShark 4.4.0 Linux, UTC was actually used. decode-executed.json records exact arguments, exit codes, hashes and source. Both commands succeeded and their output files are supplied:

```sh
tshark -r practice.pcap -T fields -E header=y -e frame.number -e tcp.stream -e tcp.segment -e tcp.reassembled_in -e http.request.method -e http.request.uri -e http.host -e http.response.code -e http.file_data
tshark -r practice.pcap -d 'tcp.port==18081,http' -T fields -E header=y -e frame.number -e tcp.stream -e tcp.segment -e tcp.reassembled_in -e http.request.method -e http.request.uri -e http.host -e http.response.code -e http.file_data
```

Use decode-command-01.stdout.txt for baseline and 02 for override. The actual records used absolute pinned executable paths; these short names require your matching PATH. The root-user stderr warning was informational. frame.time_utc prints a UTC date string; frame.time_epoch is epoch seconds. frame.time_iso 8601 is unsupported in this pinned build. No Windows command, unexecuted two-pass extraction, GUI action absent from the screenshots, or historical finding is asserted. Empty tcp.reassembled_in in these one-pass logs must remain empty in your CLI answer; visible GUI reassembly links and tabs are separate evidence.
