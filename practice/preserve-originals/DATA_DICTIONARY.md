# Resource and record dictionary

| Resource or field | Meaning |
|---|---|
| `synthetic-handling-only.pcapng.hex` | Downloadable UTF-8 hex text for an **optional synthetic**, zero-packet handling input; not a received case capture. Its matching binary is also shipped; no conversion is required. It contains no IP addresses, identity logs, or packet claims. |
| `synthetic-handling-only.pcapng` | Separate synthetic intake file, produced from the text; actual TShark 4.4.0 validation decoded zero packets with exit status zero. Do not treat a `.pcap` as this `.pcapng`. |
| `notes-template.md` | Downloadable blank intake record copied to `<case>/notes/intake.md`. |
| `<case>/notes/hash-checks.txt` | Locally generated paths, full SHA-256 values, and observed comparison statuses; not a downloadable or preverified result. |
| Received path/hash | Handoff file identity before copying; hash identifies bytes, not collector, filename, or completeness. |
| Original path/hash | Verified case reference at `<case>/original/capture.pcapng`. |
| Working path/hash | Copy from original at `<case>/working/capture.pcapng`; recorded separately even when hashes agree. |
| `MATCH` / `MISMATCH` | Equality / inequality of the two observed full digests at check time, not an investigation verdict. |
| Derivative entry | Only for a future changed file: distinct path/hash, preserved source path/hash, change and handling. None is made here. |

There is no shared dataset or packet-level schema for this lesson. The hex fixture is independent of other course fixtures.