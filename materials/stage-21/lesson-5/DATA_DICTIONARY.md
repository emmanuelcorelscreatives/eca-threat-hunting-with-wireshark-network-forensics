# Data dictionary and evidence boundaries

All scenario data and metadata are fictional offline Academy fixture material. Actual execution means software decoded the synthetic bytes, not that an incident occurred.

| File | Meaning and limits |
| --- | --- |
| build_capture.py | Offline deterministic Python builder. Reads JSON event data and writes Ethernet/IPv4 classic PCAP; sends no traffic. Uses documentation address ranges. |
| pre_action-spec.json, post_action-spec.json | Separate ordered packet specifications, version 1 and synthetic true. fixtureId and scope describe the fictional fixture, not the saved lecture case. |
| capture_manifest.json | Expected capture IDs, filenames, byte lengths, SHA-256 and frame counts. caseEvidence false explicitly excludes genuine case evidence. |
| control_record.csv | Fictional request, deployment, effective-time confirmation, independent rule presence and window agreement. None independently proves packet-level enforcement. |
| coverage.csv | Fictional collection claims, directions, gaps and blind paths; not continuous-coverage proof. |
| execution.json | Actual prior Ubuntu CLI TShark execution record: commands, version used, exit codes and output names. Its version is provenance, not a prerequisite. No native GUI execution is claimed. |
| pre_action-decoded.csv, post_action-decoded.csv | Actual saved TShark field output for 12 and 16 synthetic frames respectively. |
| pre_action-bad-frames.txt, post_action-bad-frames.txt | Empty supplied bad-frame reports, consistent with execution.json reporting no malformed/bad-checksum frames. |
| pre_action-stderr.txt, post_action-stderr.txt | Prior execution's root warning. It does not invalidate the decoded packets and does not require elevated learner privileges. |

## Event specification fields
`timestamp` is explicitly zoned time; the builder writes UTC epoch seconds and microseconds. `kind` selects transport construction. `src`, `dst`, `sport`, `dport` identify packet endpoints, not process identity. TCP `flags`, `seq`, `ack` are explicit header values. `payloadText` supplies UTF-8 bytes; these fixtures use LAB HELLO, LAB REPLY and UDP LAB BOOKEND. Port 8443 is only a port: these toy exchanges are not demonstrated TLS/HTTPS. Optional builder fields supporting other event kinds do not imply such traffic exists in this fixture.

## Decoded columns
- `frame.number`: ordinal in that source capture. Always cite capture ID plus frame; two files can have the same frame number with unrelated content.
- `frame.time_epoch`: absolute UTC epoch seconds, including fractional precision. GUI local formatting does not alter it.
- `ip.src`, `ip.dst`: packet direction; not attribution.
- `tcp.srcport`, `tcp.dstport`, `udp.srcport`, `udp.dstport`: transport endpoints; blank when inapplicable.
- `tcp.flags`: hexadecimal flags; 0x0002 SYN, 0x0012 SYN/ACK, 0x0010 ACK, 0x0018 PSH/ACK.
- `tcp.seq_raw`, `tcp.ack_raw`: raw sequence/acknowledgment values, independent of GUI relative-number display.
- `tcp.len`: TCP payload bytes, not total frame size. `tcp.payload` is hexadecimal payload.
- `ip.checksum.status`, `tcp.checksum.status`, `udp.checksum.status`: saved decoder status; 1 denotes good here, blank means not applicable. Interpret with checksum checking enabled as in execution.json.

## Record columns
In control_record.csv, `record_id` is the row citation; `time_utc` is the fictional event time. `event_type`, `actor_role`, `scoped_asset`, `claimed_action_scope`, `intended_point`, `evidence_type` and `notes` define the claim and its limits. `window_start_utc`, `window_end_utc`, `stop_decision_utc` are populated in R5. Request, deployment, effective confirmation and rule presence are distinct from independent enforcement verification.

In coverage.csv, `capture_id` joins to the manifest. `point`, `interface`, `assets`, `directions` describe claimed visibility. `claimed_start_utc` and `claimed_end_utc` are not packet endpoints or proof of uninterrupted collection. `gap_start_utc` and `gap_end_utc` identify the known post gap; empty pre gap fields do not prove no gaps. `unmonitored_path` remains unknown, not quiet. `owner_role` identifies who must answer coverage questions.

## Identity convention
Cite, for example, `LAB-CV-POST-01 / post_action.pcap / frame 8 / 2025-01-15T12:11:00.400Z`, with the manifest hash attached to the report. Working filenames and reconstructed filenames are analysis artifacts linked by verified bytes; they are not new source identities. Keep the captures separate and preserve the originals and records.