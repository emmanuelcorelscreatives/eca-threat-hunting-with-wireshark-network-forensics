# Answer Guide

**Conditional reasoning key: it checks collection scope, not packet findings.**

## Scope record

A complete record names the point, source or link, directions, T0–T1, rules, potential intersections, blind spots, and a scope-limited conclusion. Observed evidence remains blank because no file was supplied.

## Visibility key

| View | Expected reasoning |
|---|---|
| Endpoint A interface | P1 and P2 could cross while A participates during T0–T1. Delivered broadcasts or multicasts may appear; B’s unrelated unicast ordinarily does not. Promiscuous mode cannot make a switch send unrelated unicast. |
| TAP; both outputs | P2 crosses the installed gateway link; P1 need not. Both outputs cover potential directions, not proof of packets. |
| TAP; one output | Only that direction is covered. The opposite direction remains unknown. |
| SPAN includes P1 | P1 is potentially visible only when selected sources and directions cover it. P2 requires its path to be selected separately. |
| SPAN excludes B | It cannot settle P1. P2 still depends on its selections. |
| Gateway | P2 crosses; switch-local P1 need not. East-west describes direction, not a verdict. |
| Cloud interface | Unknown until its selected interface or path, directions, rules, and window are mapped. |

## Question key

1. Model wording: **the gateway view alone cannot settle whether A communicated with B**. An authorized A or B endpoint capture, or SPAN scoped to the A-to-B path, could intersect P1.

2. For a real capture only: **“No reply appears here during this window.”** An alternate return route, omitted output or mirror direction, or collection loss may explain the gap. Some SPAN selections may duplicate packets, so counts require quality checks.

3. Correlate inside observations or translation records using addresses, ports, transport protocol, and time. Clock differences or incomplete records may leave uncertainty. A public address alone identifies neither the internal device nor its process or user.

4. Record the selected source interface, permitted directions, T0–T1, and traffic-selection rules. Amazon VPC Traffic Mirroring copies matching traffic from selected source network interfaces to a target; it excludes ARP and DHCP, and bandwidth or packet-size limits can affect copies. Do not generalize those details to every cloud mirror.

5. **Statistics → Capture File Properties** checks the time range and available interface information; the physical point or settings may be absent. **Statistics → Endpoints or Conversations** summarizes addresses and exchanges in the file. A display filter only narrows displayed packets; it cannot restore packets never collected.