# Data dictionary and provenance boundaries

- `ssh-auth-practice.pcap`: classic little-endian Ethernet PCAP, microsecond stored timestamps; 27 real captured TCP packets with explicitly transformed classroom endpoint headers. No private key or decrypted application content.
- `sanitized-auth-records.csv`: UTF-8 server journal excerpt. `record_id` is an Academy reference label, not a native journal ID. `collector_received_at_utc` is journald receipt realtime; `native_embedded_event_timestamp` is intentionally empty. `timestamp_basis` describes this limitation. `event_type=accepted_public_key` identifies the single accepted-account message. Structured account/source fields are filled only for that event. Other rows retain the actual message with the lab-private-directory path sanitized. `raw_destination_*` denotes the known controlled daemon endpoint, not a claim that every message explicitly contains those fields.
- `training-address-map.csv`: explicit raw-to-classroom endpoint transformation. Addresses are documentation-only aliases. This is not NAT observation, DHCP history or asset ownership.
- `packet-transformation-proof.json`: original/derived capture digests and per-frame payload/timestamp/sequence/checksum preservation checks; the raw source is retained privately as collection evidence. Source digest alone does not let a student inspect an undistributed original.
- `lab-execution-context.json`: source-controlled collection/client lifetime and restricted lab-action outcome, with logging/clock/operator limits. This is separate context, not a packet-derived finding.
- `actual-execution-proof.json` and `*.stdout.txt`/`*.stderr.txt`: actual native Linux4.4.0 decoding runs and exact output. Running TShark as the collecting administrator can emit a root warning in stderr; student offline analysis needs no root privilege. Absolute maintenance paths in historical command records describe actual reference execution; use the local relative filenames in setup.
- `replay-records.json`, `rebuild_capture.py`: exact recorded-byte reconstruction. No network, SSH keys, package download, session recreation or overwrite of an existing output.
- `worksheet.md`: intentionally blank learner observations, not an incident report.
- `answer-guide.md`: exercise-specific observations and limits, including the absence of session closure. Interpret log receipt time and packet time separately.

The original lecture offers conditional Windows and SSH branches and states that no original case was supplied. This new supplementary SSH exercise does not alter that history or fabricate a 4624 event. No production asset names, customer records or existing user documents were collected. All new practice records came from the restricted loopback lab created solely for this course.


## Native UI length counter

The recorded Wireshark4.4.0 Properties Length counter is 8,848 bytes, while the exact PCAP file is 8,864 bytes and its captured packet data totals 8,408 bytes. See `NATIVE_UI_LENGTH.md`, the read-only verifier and SHA-bound source proof for why these quantities differ. The original screenshots and accurate UI receipts remain unchanged.
