# Data dictionary and provenance

All files are synthetic Academy training materials. `scenario.json` supplies **hypothetical design and context**, not packet-derived observations. `captureDesign` declares intended vantage, UTC bounds and visibility; No packet timing plan or fixture is included. `hosts`, `possibleApprovedWork`, `clockAssumptions` and `logAvailability` are scenario metadata. Times use ISO 8601 UTC with `Z`; zero offsets are *assumptions for this exercise*, not measured synchronization.

All CSVs use a header row, UTF-8, comma separation and globally distinct `record_id`. An empty field means **not supplied**, never a negative finding. `utc` is the authored record time; `source_host` is the machine reporting the record, not necessarily the connection destination. Matching account, host or time values are comparison leads, not causal joins.

`identity-events.csv`: `event_id` is 4769 service-ticket request or 4776 NTLM validation; `account` is a synthetic account label. `client_address`, `service` and `ticket_encryption` apply to the illustrated 4769 rows. `source_workstation` applies to 4776 and is not a destination. `status` is the illustrated result code; `0x0` denotes success in these authored examples.

`destination-events.csv`: 4624 denotes a created logon session on `source_host`; `logon_type` and `authentication_package` are recorded attributes. `source_address` and `workstation` may be empty. `logon_id` is local to its reporting host and does not join these rows to packets.

`host-events.csv`: Event ID 1 is process creation; Event ID 3 is a network-connection record. `process_id` and `process_label` identify the illustrated client process locally. `source_address`, `destination_address` and `destination_port` describe only populated connection rows. The intermediary has no supplied Sysmon data. Addresses are documentation-only; DNS hostnames end in `.test`.
