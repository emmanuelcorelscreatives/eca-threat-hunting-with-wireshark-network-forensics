# Worked answer guide

## Agreement and provenance
Hypothesis: after the claimed effective action, comparable outbound TCP/8443 communication from 192.0.2.10 will not appear on the monitored client-facing path during the agreed window. R1 is an incident-lead request at 12:00; R2 is a control-owner deployment claim at 12:02; R3 supplies the control owner's fictional effective confirmation at 12:04. All dates are 2025-01-15 UTC. R4 at 12:04:30 is independent rule presence, not proof of flow enforcement, routing or exceptions. R5 records response-owner agreement on 12:05–12:16, with a 12:16 stop for decision. Eleven minutes spans several opportunities for the observed two-minute cadence, but does not guarantee intermittent activity would recur.

Manifest checks should yield the sizes and hashes in setup.md; both rebuild comparisons should pass. Actual supplied TShark decoding has 12 pre frames and 16 post frames, no reported malformed/bad-checksum frames and successful exit codes. This is executed CLI evidence on synthetic packets, not executed GUI evidence. The root warning in stderr is not a packet error or a recommendation to use root.

Pre packet endpoints are 11:57:00–11:59:00.500; post endpoints are 12:05:00–12:16:00. Local offset is learner-measured, not a universal answer. UTC epochs are authoritative for this comparison. Coverage metadata claims lab-veth0, fictional client-facing link, 192.0.2.10, both directions, pre 11:56–12:00 and post 12:05–12:16. Post has a 12:10:00–12:10:30 gap; lab-veth1 is unmonitored. Bookend packets are not proof of continuous recording. Metadata claims and packet endpoints are different kinds of evidence.

## Packet-backed comparison
Use manifest identities with frame numbers; working copies retain source frame numbering. All following times are UTC on 2025-01-15.

| Capture and frames | Time | Direction and interpretation |
| --- | --- | --- |
| LAB-CV-PRE-01, 1–6 | 11:57:00–00.500 | 192.0.2.10:54000 → 198.51.100.20:8443 starts with SYN; frame 2 returns SYN/ACK; frame 3 completes handshake. Frame 4 sends 9 bytes LAB HELLO; frame 5 returns 9 bytes LAB REPLY; frame 6 acknowledges. |
| LAB-CV-PRE-01, 7–12 | 11:59:00–00.500 | Same peer and pattern using client port 54001. Frames 7–9 handshake, 10 outbound payload, 11 inbound payload, 12 outbound ACK. |
| LAB-CV-POST-01, 2 | 12:07:00 | 192.0.2.10:54002 → 198.51.100.20:8443, SYN only, no visible reply. |
| LAB-CV-POST-01, 3 | 12:09:00 | 192.0.2.10:54003 → original peer:8443, SYN only, no visible reply. |
| LAB-CV-POST-01, 4–9 | 12:11:00–00.500 | 192.0.2.10:54004 → 203.0.113.30:8443. Frames 4–6 handshake; 7 sends LAB HELLO; 8 returns LAB REPLY; 9 acknowledges. |
| LAB-CV-POST-01, 10–15 | 12:13:00–00.500 | Same other peer using port 54005. Frames 10–12 handshake; 13 outbound payload, 14 inbound payload, 15 outbound ACK. |

Flags are SYN 0x0002, SYN/ACK 0x0012, ACK 0x0010 and PSH/ACK 0x0018. Raw sequence numbers progress from client SYN 1000 to 1001, then 1010 after nine payload bytes; peer progresses from SYN 9000 to 9001, then 9010. These handshake and acknowledged bidirectional payload frames support established exchanges, not merely attempts. They do not establish application success beyond the visible toy data. TCP/8443 is not evidence of TLS or HTTPS.

Pre original-peer filter totals: outbound 8, return 4, combined 12. Post original-peer totals: outbound 2, return 0, combined 2. Other-peer post totals: outbound 8, return 4, combined 12; broad host filter totals 14. Post frames 1 and 16 are UDP 192.0.2.80:55000 → 192.0.2.81:55001 bookends, not scoped-host communication.

Broad TCP Conversations should expose two pre flows to 198.51.100.20 starting 11:57 and 11:59; post exposes two original-peer attempts starting 12:07 and 12:09 and two other-peer flows starting 12:11 and 12:13. Enabling Limit to display filter with the original-peer filter hides the other peer. Record actual learner GUI settings, not an imagined screenshot.

At 60-second graph resolution, pre host traffic occupies the 11:57 and 11:59 minutes with six packets each. Post broad host activity occupies 12:07 and 12:09 with one packet each and 12:11 and 12:13 with six each. Trace bins to the table above; graph alignment can vary, so verify absolute packet times. Empty bins only mean no matching packets were plotted.

## Interpretation and owners
No established original-peer exchange is visible post-action, but attempts persist. A SYN with no captured reply may be consistent with blocking, a silent/unavailable service, loss, asymmetric routing or incomplete collection. It does not prove where failure occurred or that a control blocked it.

The other peer has established bidirectional exchanges with comparable payload, port and two-minute timing. That warrants prompt incident-lead reassessment of the claimed broad outbound TCP/8443 action. It does not identify an attacker or originating process. Legitimate scheduled checks, backup/monitoring agents, shared infrastructure or a service's alternate endpoint could explain similarities. Ask the service owner whether such jobs, destinations and timing are expected; the fixture supplies no definitive service context.

Independently ask the control owner to verify enforcement at the intended gateway for these exact flows, including routes and exceptions. Ask the independent reviewer what rule-presence checking actually covered. Ask the collection owner whether both directions traversed lab-veth0, how the gap arose and what lab-veth1 could carry. Those answers are unknown here; do not invent them or choose the reassuring record over packet evidence.

## Example decision memo and measured next check
At the agreed 12:16 stopping point, report to the incident lead: original-peer attempts persist in LAB-CV-POST-01 frames 2–3; established comparable exchanges to another peer occur in frames 4–15 after the claimed 12:04 effective time. Request prompt reassessment, not a containment-success declaration. The response owner coordinates the decision; the control owner owns enforcement verification and the collection owner owns visibility confirmation. Gap and alternate-path findings remain inconclusive. No eradication or attribution conclusion is supported.

Proposed tabletop next check, subject to response-owner agreement: monitor 12:16–12:28 UTC for 12 minutes, giving six two-minute recurrence opportunities; collection owner targets both directions on lab-veth0 and lab-veth1 with zero unexplained gaps and records any deviations. Analyst reviews 60-second bins and source packets every two minutes; control owner supplies flow-specific enforcement and exception evidence by 12:28. Incident lead reassesses immediately on any comparable established exchange, otherwise at 12:28 with explicit coverage accounting. This is a recommendation, not additional supplied capture coverage or a claim that those checks happened. Longer observation cannot repair today's missing visibility.

The unchanged lecture's own saved case still has no post-action capture or action record. These fictional supplemental results cannot be transferred to that case.