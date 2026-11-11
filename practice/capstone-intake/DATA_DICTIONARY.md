# Data dictionary and design checks

Both CSVs are synthetic UTF-8 records with one header row. IDs are scenario identifiers, not observed host identities. Addresses use documentation-only space; an inventory claim is not a verified mapping.

**`asset-inventory.csv` — four designed data rows.** `asset_id`: unique designated asset ID. `role`: stated business function. `owner`: fictional role for confirming exceptions. `expected_relationships`: brief’s expected service relationships, not observed connections. `address_mapping_status`: claimed documentation address or explicitly absent mapping; neither establishes current attribution.

**`capture-register.csv` — three designed data rows.** `capture_id`: unique listing ID. `stated_source`: source named by the intake listing or plan. `claimed_start`, `claimed_end`: UTC ISO 8601 bounds asserted for that entry, not measured packet timestamps. `observation_point`: claimed or proposed place of observation, not all-path coverage. `disclosed_limits`: stated visibility or availability constraint. `status`: `Listed not supplied` means no file was delivered; `Planned not collected` means collection is not asserted.

Expected structural check: inventory headers are `asset_id,role,owner,expected_relationships,address_mapping_status`; register headers are `capture_id,stated_source,claimed_start,claimed_end,observation_point,disclosed_limits,status`. These counts and headers describe the authored files; no validation command has been executed.