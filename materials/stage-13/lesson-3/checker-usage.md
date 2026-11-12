# Independent read-only packet checker

`check_capture.py` parses the existing classic Ethernet PCAP separately from `offline-builder.py` and compares it with the actual `executed-fixture-spec.json`. It neither builds a capture nor sends traffic, and it does not authorize inspection of anyone else's file. Its supported checks are bounded IPv4/TCP and DNS-over-UDP fixture cases, not a universal Wireshark/PCAPNG validator.

A learner can run the packaged copy read-only:

```sh
python3 check_capture.py --capture practice.pcap --spec executed-fixture-spec.json
```

The actual recorded invocation in `independent-pcap-execution.json` uses a retained checker path. The packaged `check_capture.py` has that recorded checker hash, but do not describe the short recipe above as the literal historical argv. `independent-pcap-report.json` retains the actual successful report, including the source hash and spec binding. Existing files are not rewritten by this checker.

## What this fixture's report establishes

The PCAP SHA-256 is `741a40d9c1d1d3e3361b2bc4a670b9a5cd7d2e3b1e9d60d215d356b6e9417eb4`. The report checks all **33** records, timestamp order and exact spec values, frame lengths and tuples, raw TCP flags/sequences/ACKs/payload bytes, and included IPv4/TCP checksums. Its physical and captured-frame totals are **2,378** and **1,826** bytes, respectively. These are separate from the recorded native Properties Length of **2,362** bytes.

The same-tuple retry assessment identifies original frame **19** repeating frame **18**'s source port **43102**, peer `203.0.113.30:8080` and raw SYN sequence **3200**. It must not become an additional distinct connection start. `rawAckContinuityChecks` only compares ACK values with reverse-direction sequence ends actually present in earlier captured bytes. It does not prove unseen earlier ACK history; any unestablished prior coverage remains unresolved.

The report's bounded HTTP byte-origin check identifies the captured GET header in original frame **4**. It does not turn zero-payload probes in **12/24/28** or their replies into new application requests. One visible request cannot supply a successive request interval. Decoded HTTP details and the separate source-bound field export corroborate the original frames; a parser is not an endpoint process or purpose record.

`independent-checker-rejection-proof.json` retains four rejected altered scratch inputs: bad IPv4 checksum, bad TCP checksum, changed first timestamp and truncated final frame. The original stayed unchanged. These are bounded rejection tests, not proof of every possible failure mode.

## Limits

A passing report does not establish real incident provenance, authorization, collector coverage, zero drops, clock accuracy, an application's schedule, process identity, command-and-control, GUI operation, public repository placement, main-visual approval or completed learner homework. Keep the original packet file unchanged when a check fails and inspect the exact input/spec mismatch. Do not edit an expected answer to make a different capture pass. Refer to `native-validation.md` for actual native views and `answer-guide.md` for qualified synthetic results; use a separate source record and worksheet for each authorized-file assessment.
