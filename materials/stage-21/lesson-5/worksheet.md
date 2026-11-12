# Student worksheet

All answers concern the fictional fixture unless explicitly marked saved-lecture limitation. Times below should be reported in UTC with measured display offset retained.

## 1. Agreement before inspection
- Hypothesis, scoped asset, protocol, direction and monitored path: ____
- Request time/owner: ____ Deployment time/owner: ____
- Claimed effective time and confirming owner: ____
- Independent rule-presence evidence and what it does not establish: ____
- Agreed observation window, response owner and stopping decision time: ____
- Why is that duration relevant to the earlier cadence, and why is silence still limited? ____

## 2. Preservation, time and coverage
- Manifest verification and byte-identical rebuild results: ____
- Pre source ID/hash, count, first/last packet UTC times: ____
- Post source ID/hash, count, first/last packet UTC times: ____
- Same-frame local display, UTC display, measured local minus UTC offset and zone: ____
- Claimed collection point/interface/asset/directions: ____
- Recording gap and unmonitored path: ____
- Why do packet-time endpoints not prove continuous coverage? ____

## 3. Compare packets
Use these display filters separately in each capture:

Outbound original peer:
`ip.src == 192.0.2.10 && ip.dst == 198.51.100.20 && tcp.dstport == 8443`

Return original peer:
`ip.src == 198.51.100.20 && ip.dst == 192.0.2.10 && tcp.srcport == 8443`

Combined original peer:
`ip.addr == 192.0.2.10 && ip.addr == 198.51.100.20 && tcp.port == 8443`

Broader host scope:
`ip.addr == 192.0.2.10 && tcp.port == 8443`

For the other peer, repeat both directional filters replacing 198.51.100.20 with 203.0.113.30. Record filter scope and counts, not just a conclusion.

| Source ID and frames | UTC time(s) | Source:port → destination:port | Flags and data | Attempt or established exchange? |
| --- | --- | --- | --- | --- |
| ____ | ____ | ____ | ____ | ____ |
| ____ | ____ | ____ | ____ | ____ |
| ____ | ____ | ____ | ____ | ____ |
| ____ | ____ | ____ | ____ | ____ |

- Earlier cadence and defining pattern: ____
- Post original-peer attempts versus replies: ____
- Other-peer similarities and differences: ____
- What does TCP/8443 alone not tell you about application or process? ____

## 4. Broaden and trace
Learner GUI instructions: open **Statistics → Conversations**, inspect TCP conversations first with the display filter cleared or **Limit to display filter** disabled. Record that checkbox state: ____. Then enable it with the original-peer filter and explain what disappears: ____. Record host peers, ports and start times: ____.

Open **Statistics → I/O Graphs**. Plot the broad host filter and original-peer filter at a 60-second interval, using comparable time axes in the separate files. Record interval and scope: ____. Locate two-minute-spaced activity and trace each interesting bin to source packets: ____. Explain why an empty bin does not prove blocking or continuous collection: ____.

## 5. Challenge the interpretation
- Ordinary explanation involving shared infrastructure or a legitimate service: ____
- Ordinary explanation involving scheduled timing: ____
- Service-owner question that could distinguish these possibilities: ____
- Independent control-owner question about actual enforcement, intended point, routing or exceptions: ____
- Independent collection-owner question about missing directions, gap or alternate interface: ____
- Which answers are unavailable in this fixture and must remain unknown? ____

## 6. Decision memo
Write a bounded finding, citing source frames, times and directions: ____.

Does this call for prompt reassessment, enforcement checking or a limited negative finding? Why? ____

Decision owner: ____ Action owner: ____ Coverage owner: ____

Agreed stopping point: ____. Proposed next monitoring interval, cadence rationale, responsible owner, packet review frequency, measurable coverage target and next decision time: ____.

What cannot be concluded about enforcement, attribution or eradication? ____

Saved lecture case limitation, distinct from this fixture: ____.