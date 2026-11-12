# Scope worksheet

**Hypothesis:** A connection involving JUMP-BETA might precede a hop to SSH-GAMMA. The approved administrator session is a competing explanation for **some**, not necessarily all, traffic. Work only with this synthetic case; use Project 6 evidence separately if it becomes available.

1. For **each** capture, enter observation point, actual first/last packet times, hypothetical route/window from coverage records, clock uncertainty, and any unmeasured collection limits. Do not combine the observation points or equate first/last packets with full visibility.
2. In Wireshark, inspect TCP Conversations, then filter `ip.addr == 192.0.2.10 && ip.addr == 198.51.100.20 && tcp.port == 3389`; repeat with `192.0.2.11` instead of `.10`. In B use `ip.addr == 198.51.100.20 && ip.addr == 203.0.113.30 && tcp.port == 22`. Narrow by displayed UTC time. For each candidate record **capture filename, actual frame numbers in both directions, endpoints, ports, and interval**. Use your own decoding before consulting the supplied key; cite each file separately.
3. For each address, cite the assignment row valid at that time. Match a candidate to the **destination's** authentication record by destination, source if recorded, and a clock-tolerant window. Record what the log says separately from whether it identifies that particular TCP flow. Compare JUMP-BETA host activity and the administrator plan; identify matches, conflicts, and missing evidence.
4. Fill three groups: **corroborated activity** (specify exactly what sources support), **contacted but access/identity unresolved**, and **outside available coverage**. These are not compromise verdicts. For each claim write: packet reference; record ID; alternative explanation; confidence **in that claim**; limit; next action.
5. Request time-matched assignments if device ownership is disputed; SSH-GAMMA destination authentication and relevant host records if its access is disputed; account ownership and session linkage if identity or a hop is disputed; and a later B observation if the gap matters. Give narrow windows and say how each answer changes scope.

Handoff: **Observed:** ____ **Combined records support:** ____ **Unresolved:** ____ **Targeted collection and scope effect:** ____. A negative review must name its observation point, interval, and filter; it is not an all-clear.

## Submission

Submit the two coverage rows, three candidate cards, three-group scope map, a claim-specific confidence table, competing administrator explanation, and four-part handoff. For each narrow collection request include the exact destination, UTC interval, requested source and the scope change each possible result would justify. If later authorized incident evidence becomes available, repeat this method independently; these fixture results do not carry over.
