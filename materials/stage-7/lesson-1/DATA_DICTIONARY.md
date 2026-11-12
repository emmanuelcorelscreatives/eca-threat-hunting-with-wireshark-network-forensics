# Data dictionary

All addresses use the documentation-only `192.0.2.0/24` network; names use `.test`. Asset labels and team names are fabricated. The builder derives locally administered Ethernet addresses from IPs; those labels do not identify manufacturers, owners or a physical topology.

**`synthetic-role-events.json`:** synthetic version-1 builder input. Each ordered event has a UTC `timestamp`, `kind`, `src` and `dst`. DNS events add ports, `name` and `transactionId`; answers add `answer`. ICMP events add `identifier`, `sequence` and optional `payloadText`. TCP events add ports, `flags`, `seq` and `ack`. The TCP design is a handshake only: it asserts no TLS or application exchange.

**`synthetic-asset-inventory.csv`:** `record_id` is a scenario record identifier; `ip_address` is its proposed assignment; `asset_label` is an inventory label, not a packet observation; `role` is workstation, resolver, server or network_device; `valid_from_utc` is inclusive and `valid_until_utc` exclusive. A blank bound means **unknown**, not indefinitely valid. `owner_team` and `mapping_source` are fabricated scenario assertions, not real owner confirmations. Overlapping I08/I09 must both be retained.

**`synthetic-capture-context.json`:** non-packet-derived, authored scenario metadata. Its designed UTC window must be checked against generated packet times. `observationPoint` and `coverageLimit` are not evidence that a real collector saw all traffic.

**`role-mapping-worksheet.csv`:** eight prelisted observed IP addresses; all evidence and classification cells remain learner work. Packet references and first/last address times must come from decoded packets. Capture-wide first/last UTC times, observation point and missing collection details have separate fields. `inventory_record_ids`, `inventory_sources` and `proposed_roles` preserve semicolon-separated entries in corresponding order, including both conflicting candidates. `classification`, `alternatives`, `confidence` and `next_record_or_action` keep uncertainty visible. Do not fill observation fields from inventory alone.

**`expected-results.json`:** checked packet count, packet bounds, address frame lists and capture hashes; classification fields are explicitly synthetic metadata. **`execution-proof.json`** records actual local tool runs. Saved `.stdout.txt`/`.stderr.txt` are local command receipts, not learner executions or GUI proof.
