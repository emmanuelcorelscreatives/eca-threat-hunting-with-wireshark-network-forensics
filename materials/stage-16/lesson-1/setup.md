# Setup and bounded inspection

Unzip the complete kit. Open a terminal in this directory. Use Python 3.10+; no virtual environment or pip step is necessary for these standard-library tools. Install Wireshark/TShark 4.4 separately through your approved software process if absent. Check `tshark --version` before interpreting version-specific behavior. Actual production run details are in execution-proof.json and preserved command logs.

```
python3 tools/check_capture.py --scenario scenario.json --capture practice.pcap --tshark tshark
python3 tools/build_capture.py --scenario scenario.json --output rebuilt.pcap
cmp rebuilt.pcap practice.pcap
```

The builder creates only a new file and refuses an existing output; choose a fresh filename for another run. The checker reads the PCAP independently, checks raw record lengths and network checksums, compares session addresses, ports, timestamps, raw TCP sequence/acknowledgment numbers, flags and exact payloads against scenario.json, then checks decoded DNS, HTTP, retransmission and bounds with TShark. A success is fixture consistency, never a security verdict.

Copy practice.pcap to a working filename and open that copy with File → Open in Wireshark 4.4. Record its filename and SHA-256 in the worksheet. Use View → Time Display Format → UTC Date and Time of Day, and record the workstation timezone separately. Epoch comparisons below avoid local interpretation of absolute date strings. If you instead use absolute date strings, convert the UTC interval into the workstation's local timezone first; UTC display alone does not change absolute-filter interpretation.

The authorized synthetic interval is [2025-02-12 10:00:00 UTC, 2025-02-12 10:10:00 UTC), epochs [1739354400,1739355000). Apply:

```
ip.addr == 10.77.0.15 && ip.addr == 198.51.100.44 && frame.time_epoch >= 1739354400 && frame.time_epoch < 1739355000
```

Inspect transport direction, flags, raw sequence and acknowledgment numbers. Record the established conversation separately from the SYN-only attempt; its repeated SYN is one same-tuple retry, not another check-in. Remove only `ip.addr == 198.51.100.44` to retain this host and time bound. Go to Statistics → Conversations, choose TCP, check Limit to display filter and record that setting. Address pairs can contain multiple transport sessions. Compare the bounded table with the unbounded table to identify the excluded control stream. Restore the same bounded scope afterward.

Add `&& dns` to the bounded host scope. Select frame 2 and expand Domain Name System → Answers. Check both A records from this one response, transaction and name. Then inspect `&& http`, select the visible request, and use Analyze → Follow → HTTP Stream (or TCP Stream). Record the actual request Host, response and stream; this dialog changes the filter. Close it and restore the bounded host filter before another pivot. The supplied Follow CLI log is an independent text observation, not a GUI transcript.

Investigate the nearby peer but do not retain a relationship supported only by timing. Complete the worksheet and stop when a link cannot be checked. The original narrated case remains unavailable and inconclusive. A separate learner assignment is to repeat this procedure on an explicitly authorized capture with recorded observation metadata; this supplied practice does not claim the learner has done so.
