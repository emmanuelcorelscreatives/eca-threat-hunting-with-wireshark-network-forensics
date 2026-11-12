# Data dictionary

`timeline.csv` is intended to contain one filtered packet per row, in this fixed order:

| Column | Meaning and limit |
|---|---|
| `frame.number` | Reference within the recorded source capture; not globally unique. |
| `frame.time_epoch` | Packet arrival time as exported epoch text; preserve recorded characters. |
| `ip.src` | IPv4 source, if exported; blank alone does not identify another address family. |
| `ip.dst` | IPv4 destination, subject to the same limit. |
| `dns.qry.name` | Decoded DNS question name, if present. |
| `dns.a` | Decoded A-answer value(s), if present; a blank is not a finding. |

Export policy: comma separates columns, double quotes protect CSV values and double embedded quotes, `occurrence=a` requests all occurrences, and a semicolon joins repeated values **within one cell**. Empty fields retain their column positions. Keep TShark's default control-character escaping. CSV quotes do not neutralize spreadsheet formulas; import every column as Text with formula evaluation off. Capture filename, hashes, scope, filter, and command belong in the worksheet, not these six columns.

`dns-baseline-spec.json` is the exact consumed synthetic version-1 builder input for the six-frame fixture. Its ordered events specify UTC timestamps, reserved `.test` names, documentation-network IPv4 endpoints, UDP ports, transaction IDs and one `answer` per answer event. Actual raw decoding and recorded TShark exports confirm frame references in this release. `repeated-a-spec.json` is a separate two-frame input whose response uses an ordered `answers` list. `dns-baseline-controls.json` records measured local coursework controls, not historical observations or learner success. `execution.json` records actual commands and retained hashes; the 19MB full field registry remains in author history while `supported-fields.txt` supplies its exact six matching abbreviation lines. The safe runner checks your own installed registry again.

`import-drill.csv` follows the six-column layout but is independent hypothetical text with absent frame/time references. Its repeated-value cell is not packet evidence. Actual packet-level repetition is supplied separately by `repeated-a.pcap` and its checked occurrence exports.
