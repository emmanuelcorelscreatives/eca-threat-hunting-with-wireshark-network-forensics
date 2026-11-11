# Setup and Resources

No case packets were supplied. This activity creates a capture-bounded plan, not a finding of beaconing, malware, command and control, process identity, or activity beyond a file. Use an isolated environment and no private production data, credentials, or identifying information.

## Downloadable resources

- Required package files: `setup.md`, `worksheet.md`, and `answer-guide.md`.
- Verified public repository: https://github.com/emmanuelcorelscreatives/eca-threat-hunting-with-wireshark-network-forensics
- Optional input: repository-relative `practice/dns-baseline/README.md` and its included six-packet synthetic DNS fixture. This is supplemental, not a case capture. Use the README to identify the actual capture filename; none is assumed here.
- Shared prerequisites: course-supported Wireshark, TShark, and capinfos. Record versions used: ____________________

## Load and inspect

1. Open the optional fixture, or an independently authorized capture, in Wireshark.
2. Select **Statistics > Capture File Properties**. Transcribe first/last packet times, duration, and available collection details.
3. Select **Statistics > Conversations**. Inspect IP relationships and verify the host and peer from context. Create a display filter containing both endpoints with fields matching the address family; then check visible directions.
4. Review protocol details before classifying packets. Use **Statistics > I/O Graphs** only to locate activity and return to the packets.

After assigning `CAPTURE` to the README-identified file in the supported environment, these checks may be run locally; no execution is claimed here:

```text
capinfos -c -a -e -u "$CAPTURE"
tshark -r "$CAPTURE" -T fields -e frame.number
```

For the verified supplement, six frame-number lines is the control total. Stop and record a mismatch. Independently authorized captures have no preset counts or times. Do not calculate inter-arrival timing in this lesson.