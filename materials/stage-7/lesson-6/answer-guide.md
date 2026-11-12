# Checked instructor guide for the supplemental fixture

These observations concern only the packaged synthetic files. They cannot rank the missing lecture case. The read-only binary checker and independent native TShark dissections were actually executed; no Windows run is claimed. See verified-two-capture-results.json and each file's frames/stats logs. Times are UTC.

normal-day.pcap contains 23 frames, 1416 captured packet bytes, 1808 filesystem bytes, from 2025-02-03 15:00 to 21:00. practice.pcap contains 25 frames, 1559 captured packet bytes, 1983 filesystem bytes, from 2025-02-04 20:15 to 20:45. File size and summed packet lengths are different units.

| File | Lead | Actual frames | Packets | Packet bytes |
|---|---|---|---:|---:|
| normal-day.pcap | backup | 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 | 11 | 774 |
| normal-day.pcap | monitoring | 1, 2, 3, 4, 5, 6, 7, 19, 22, 23 | 10 | 540 |
| normal-day.pcap | unexplained-peer |  | 0 | 0 |
| practice.pcap | backup | 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 | 11 | 774 |
| practice.pcap | monitoring | 1, 13, 25 | 3 | 162 |
| practice.pcap | unexplained-peer | 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 | 10 | 572 |

All figures above cover each full capture. The normal-day matched 20:15–20:45 window is frames 7–22 inclusive: 16 packets, 1038 packet bytes. It contains the same eleven-frame 774-byte backup conversation, three collector packets (7,19,22;162 bytes), and routine workstation packets (20,21;102 bytes). The incident full 30-minute slice has the backup at frames 2–12, monitoring 1,13,25, and unexplained-peer 14–23; routine role comparison is incident frame24. The unexplained pair has zero normal-day frames, including in the matched window. Absence is bounded by this fixture; it is not a first-ever contact claim.

The backup transfers synthetic payload from repository to backup host: inspect directions rather than assuming outbound upload. Both backup conversations span 0.2 seconds, with coherent handshake and closure. TCP payload totals are 180 bytes, distinct from 774 packet bytes. The incident unexplained conversation spans 0.18 seconds and carries 32 bytes of synthetic payload. These do not establish real application purpose, process identity, content theft, or maliciousness.

A defensible first investigation is unexplained-peer: limited matched-window rarity plus unknown owner, schedule and process leave its explanation unresolved. Confirm the owner and obtain host/process records for the time; an authorized task could lower priority. This is a conditional judgment, not a universal score.

Backup may wait because INV-B and dated JOB-I join to the observed host, peer and approved 20:20–20:40 window; JOB-N supports comparison. Inventory labels high sensitivity, so keep the caveat: schedule approval does not prove completion or content; incident owner confirmation and process telemetry remain missing. Reopen for a conflicting destination/time or owner rejection.

Monitoring may wait because INV-M and DEV-M identify the collector and configuration; matched windows each contain quarter-hour collector events at 20:15,20:30,20:45. DEV-M is synthetic metadata, not packet-derived process attribution. Reopen for changed destination, cadence or conflicting device records. Either order among these lower leads can be defended by sensitivity and corroboration.

Protocol Hierarchy layers overlap; IP pairs are broader than transport conversations; Endpoints tabs define their own units. Record full versus displayed scope for every result. A minute graph locates narrow events better than five-minute aggregation; both can hide subsecond structure. Graph bytes mean matching packet bytes, never unique content. Students must inspect their actual graph controls; the author CLI packet totals do not establish a GUI graph configuration. Keep observations, context, inferences, missing telemetry, next test and reopening condition separate in every log row.
