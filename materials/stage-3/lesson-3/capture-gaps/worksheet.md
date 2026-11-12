# Worksheet — evidence quality

**Hypothesis:** Does the inspected window preserve enough of A's request and B's possible reply to answer whether reply content is visible? Compare the three *synthetic* views; do not treat their names as proof of completeness.

For each working copy, record source path, original-file hash computed locally, authored observation-point label, first/last saved-packet times, and any available interface or collection details. In Wireshark open **Statistics → Capture File Properties**. Write `not available` for absent fields; file properties do not establish network-wide coverage.

| View | Relevant frame references, `frame.len` and `frame.cap_len` | A→B visible? | B→A visible? | Drop field, source and covered interval—or `not available` | Answerable claim and limit |
|---|---|---|---|---|---|
| Complete | | | | | |
| Truncated | | | | | |
| One-sided | | | | | |

Clear display filters, including any applied by Follow Stream. Enter `frame.cap_len < frame.len`; inspect any matches' frame details and note where saved bytes end. Compare the same endpoints, ports, and time scope in both directions. An ACK of unseen data or a TCP analysis warning describes what this saved view lacks; it does not by itself establish collector drops, network loss, or malicious interruption. Check whether the window began late or ended early.

Write a reviewable note for each view: question; working-copy source and actual frame references; observed bytes, packets, and directions; missing telemetry; possible alternative explanations; confidence in the **specific** endpoint, timing, or content claim; and one evidence request most likely to change it. Where appropriate, distinguish “no reply is visible in this saved view” from the unsupported “B sent no reply.” Finish by identifying what a later comparison with other clocks would need; clock comparison belongs to the next lesson.