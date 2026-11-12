# Synthetic data dictionary

All identifiers and addresses are invented for this lesson. IPv4 addresses use documentation space. CSVs are UTF-8 with headers; timestamps are UTC ISO 8601. Blank cells mean **not recorded**, not disproved. Join asset IDs exactly across files. These records describe the designed scenario; validate address mappings and activity records independently for any real investigation.

**asset-inventory.csv:** `asset_id` is a synthetic stable asset key; `ipv4` is its proposed address for the scenario window; `role` describes inventory function, not SMB client/server direction; `expected_smb_peers` is a pipe-separated list of documented asset peers; `expected_shares` uses `offering-asset:share`, whether this row's asset offers or accesses it; `owner_role` is the team to consult, not a person; `record_status` is `complete` or `incomplete` for this exercise snapshot. Even `complete` is not proof that exceptions cannot exist.

**approved-activity.csv:** `activity_id` is a synthetic key; `start_utc` and `end_utc` bound the scenario approval window; `source_asset_id` and `target_asset_id` give intended exchange direction; `share` names the intended target share; `purpose` describes the fictional business explanation; `approver_role` names a fictional approving function; `status=approved` means approved **within this exercise's context only**, not a real-world authorization attestation.

**scenario-plan.csv:** `scenario_id` identifies an intended exchange; `planned_request_utc`, `client_asset_id`, `server_asset_id`, and `share` specify what a future capture must encode; `planned_response=SUCCESS_DESIGN` requests a matching successful Tree Connect response, not a measured status; `context_basis` points to the intended comparison. No row is packet evidence or host/identity telemetry.

## Executed supplemental fixture

The original scenario-plan.csv is retained as design context; SUCCESS_DESIGN is not a native packet field. Actual executed decoding is in command-2.stdout.txt. Capture identity, exact regeneration and tool provenance are in execution.json. SMB2 response status 0x00000000 is a synthetic authored success. Message ID is the TShark field smb2.msg_id. Native images validate Linux GUI behavior only and do not assert Windows execution.
