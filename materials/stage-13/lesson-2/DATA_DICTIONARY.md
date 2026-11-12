# Timing worksheet and fixture dictionary

## Sources, identity and evidence limits

`practice.pcap` is an actual packaged, explicitly **synthetic** offline Ethernet/IPv4/TCP file: 26 frames, 1,542 captured-frame bytes and 1,982 filesystem bytes, SHA-256 `de49b4bc93e17959c8bfad00ad38b580e358d0e8f4adb8c5c90e375b413b72a0`. `scope-card.md` supplies the authored client `192.0.2.10`, peer `198.51.100.20`, scoped peer TCP destination port `80`, UTC window and client-facing-link scenario description. The description is not packet-derived proof of a real observation point, capture coverage or clock calibration. The original narrated incident file was not supplied; a learner's own authorized capture is future, separate work.

`executed-fixture-spec.json` is the actual synthetic specification used for the recorded matching rebuild. Its ordered `events` have UTC ISO-style `timestamp`, `kind`, `src`, `dst`, `sport`, `dport`, TCP `flags`, **raw** `seq` and `ack`, and optional UTF-8 `payloadText`; an omitted payload is empty. All **26 events in this fixture** are TCP, although the builder supports other kinds. The specification's purpose, scope and observation point are authored metadata, not independent incident findings. `fixture-plan.json` is an earlier design alias; its presence does not show that a command naming it ran.

The current `offline-builder.py` has SHA-256 `287db0760fd6042f4fe0ab58617ccf6df2b9bdc2f1744a1847348a776329a85c` and exclusively creates output. `builder-safety-and-rebuild-execution.json` records its fresh matching rebuild and overwrite-refusal tests. The older, immutable `historical-actual-execution-proof.json` describes an earlier builder and older prose, mistakenly lists `headers: []`, and is **not** the current inventory. `source-copy-provenance.json` documents that history. The independent parser is the supplied read-only `check_capture.py`; `independent-pcap-execution.json` records an execution of its hash-matching private source under a different filename, and `independent-pcap-report.json` is the retained report. Do not infer that a proposed learner command using the copied filename was executed literally.

`all-frames.stdout.txt` exports original `frame.number`, decimal Unix seconds in `frame.time_epoch`, a human-readable `frame.time_utc`, streams, IPs, ports, raw TCP numbers, frame and TCP lengths, payload and HTTP fields. It does not export TCP flags or checksum status; see `decoded-fields.stdout.csv` and the independent raw-byte report for those checks. `frame.time_utc` is **not** an executed ISO-8601 field. The PCAP has microsecond timestamp precision even when a field export pads decimals to nine fractional digits; neither precision nor matching synthetic timestamps proves clock accuracy. The independent report explicitly leaves frame 1's ACK without a prior observed reverse sequence end. File validation is not collection or authorization validation.

## Submit the source-and-scope metadata **with** `worksheet.csv`

The actual `worksheet.csv` has **16 headers and no learner rows**. Its existing columns do **not** contain a separate capture-hash or peer-port column. To keep the supplied header intact, put the following explicitly labelled block in the learner's **submitted copy of `worksheet.md`**, alongside the completed CSV. This companion block is mandatory; a CSV submitted alone does not record all required source and scope information. Leave learner entries blank until the learner verifies their own source. Do not put a port into the IP-only `scope_peer` cell or silently substitute a working-copy filename for the original's identity.

```text
Original capture filename: __________
Original capture SHA-256: __________
Opened working-copy filename: __________
Opened working-copy SHA-256: __________
Scoped client IP: __________
Scoped peer IP: __________
Scoped peer TCP destination port: __________
Capture window and time zone: __________
Capture point and basis for that description: __________
Collection, clock, missing-direction, loss and address-mapping notes: __________
```

For **this fixture's worked answer only**, the original filename is `practice.pcap`, its hash is the SHA-256 above, and the scoped peer TCP destination port is `80`. Do not transfer those values to a different authorized capture. Record the original file's hash before analysis, verify that the working copy matches, and preserve both identities in the submitted companion. A future real-capture submission also needs authorization and collection context; a passing synthetic checker is not a substitute. The supplied `worksheet.md` provides this companion record. Keep `worksheet.csv` header-only until the learner enters their own results; its existing 16-column header stays unchanged. Record the opened-copy SHA-256 and compare it with the approved original SHA-256 before analysis.

## Existing CSV headers, in file order

Add learner rows without replacing the header. An excluded packet may have a known *observed packet time* in its reason, but it must not acquire a fabricated *accepted start time* or interval. Keep connection attempts and request starts in separate series.

| CSV column | Meaning and entry rule |
| --- | --- |
| `source_capture` | Filename of the authorized working copy actually opened for analysis. The accompanying metadata block separately records the original filename and SHA-256 and the opened working-copy filename and SHA-256, including the comparison result. |
| `scope_client` | Scoped client IP, checked against packet Source and any authorized address mapping. |
| `scope_peer` | Scoped peer **IP**, checked against packet Destination. Record the peer destination **port in the companion block**, not as part of this IP cell. |
| `capture_window_utc` | UTC window or a clearly documented conversion from the capture's stated time zone. Check coverage at both boundaries. |
| `capture_point` | Documented observation-point context and its basis; this fixture's point is authored metadata. |
| `original_frame_number` | Original, unfiltered source-frame number, never a renumbered filtered-row position. For a split request, use its first-byte frame and identify the decode frame in `reason`. |
| `timestamp_epoch_seconds` | Decimal epoch seconds for a **confirmed start** under the recorded rule. Do not turn the first visible packet of a midstream flow or a later segment into an exact missing start. |
| `candidate_event_type` | `TCP connection attempt`, `HTTP request start` or `non-start packet`. Type alone does not imply acceptance. |
| `tcp_stream` | Observed Wireshark stream identifier where applicable. A stream is one conversation and may contain multiple requests. |
| `status` | `accepted`, `excluded` or `uncertain`; an uncertain possible start is not silently accepted. |
| `reason` | Packet-based keep/exclude/uncertain rationale, including retry, tuple and scope checks, missing first bytes, decoded-row versus first-byte frame, or a non-start. Preserve candidate exclusions. |
| `timestamp_rule` | For accepted rows, consistently use `SYN first attempt` **or** `first observed request bytes` within its separate series. An `http.request` decode row is not automatically a first-byte frame. |
| `start_certainty` | `confirmed` or `uncertain` for a possible start; leave inapplicable non-start entries blank. Explain uncertainty rather than guessing. |
| `previous_accepted_frame` | Previous **accepted, same-event-type, same-client, same-peer and scoped-port** start in time order; blank for the first in each series. |
| `interval_seconds` | Current accepted epoch minus that preceding accepted epoch; blank for a first, excluded or uncertain event. Never mix SYN and request times. |
| `limits` | Window, clock, missing direction or bytes, dropped-packet possibility, translation, decoding, source and attribution qualifications. |

`frame.len` is the reported original frame length, including headers; `frame.cap_len` is the number of frame bytes actually stored in the capture. They are equal for every frame in this untruncated fixture; they need not be equal in another capture. `tcp.len` describes TCP payload bytes. They are neither an HTTP body length nor PCAP filesystem size. `tcp.seq_raw` and `tcp.ack_raw` are wire numbers, whereas the native GUI may display relative sequence numbers. HTTP reassembly can move a *decoded request row* later than the *first observed request bytes*. The time between confirmed starts is `Δᵢ = tᵢ − tᵢ₋₁`; a single confirmed event has no interval. If capture begins midstream, misses a direction or has too few comparable starts, record the limitation and report timing unresolved rather than manufacturing a series.