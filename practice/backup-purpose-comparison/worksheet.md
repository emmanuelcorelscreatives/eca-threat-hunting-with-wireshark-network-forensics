# Worksheet — test the purpose, not the byte count

**Hypothesis:** Is the scoped `192.0.2.10` → `198.51.100.40` connection explained by approved activity? First note the authored capture point and limits in `setup.md`. Inspect the supplied PCAP or your verified rebuilt copy before citing frames. From Wireshark, enter actual frame numbers, start/duration, directional packet and byte counters, and any visible content: __________. Record the display filter and whether Conversations used it: __________. Which return packets carry acknowledgments, and is there return payload? __________. Counters include overhead; acknowledgments are not proof of an authorized upload.

Read the **synthetic scenario metadata** in `synthetic-activity-records.csv`. For each candidate, compare asset role, destination, time and an independent link to this particular activity. Mark **supported, contradicted or unresolved**, with a reason; one policy match alone does not establish authorization.

| Explanation | Matching record and packet evidence | Contradiction or missing link | Assessment and specific owner request |
|---|---|---|---|
| Backup |  |  |  |
| Synchronization |  |  |  |
| Administrative transfer |  |  |  |

Challenge the leading explanation: could backup use another documented path, sync use an unapproved account, or an approval cover only another asset or time? Could a familiar service carry unauthorized activity? Note clock or capture-scope uncertainty rather than converting missing logs into proof of wrongdoing.

**Provisional note — separate layers:** Packet layer (cite only inspected frames and visible content): __________. Business layer (record IDs; matches and conflicts): __________. Unknown layer (account, run, task authorization or content not established): __________. State the next smallest useful request to each relevant owner, sharing only necessary case details. Is purpose established, contradicted or unresolved? __________. Keep observed traffic bytes separate from any claim of sensitive-data loss. The next lesson addresses the data-loss confidence level.