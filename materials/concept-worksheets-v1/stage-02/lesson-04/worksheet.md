# Collection-View Worksheet

**Synthetic exercise: illustrative topology, not a capture or finding.**

> To test whether Endpoint A contacted an external peer and communicated with Endpoint B, mark the recording point and time window before opening Wireshark, the packet-analysis tool.

> Both endpoints are network devices; the diagram is a teaching example, not a capture or finding.

## Routes to evaluate

```text
Endpoint A ─┐
            Switch ─ Gateway ─ External peer
Endpoint B ─┘
```

- **P1:** proposed Endpoint A ↔ switch ↔ Endpoint B route (switch-local)
- **P2:** proposed Endpoint A ↔ switch ↔ gateway ↔ external-peer route

Neither route is asserted to have occurred.

> A network TAP is a device that observes only its installed link.

> A switch mirror, or SPAN, copies traffic from selected source ports or VLANs—virtual network groups—to a monitoring port.

## 1. Scope record

Complete this before making any absence claim.

| Field | Meaning | Learner entry |
|---|---|---|
| Observation point | Where the recorder stood | __________ |
| Selected source/link | Interface, SPAN source, cloud source, or TAP link | __________ |
| Directions | Recorded output or direction(s) | __________ |
| Window | Symbolic T0–T1 | __________ |
| Selection rules | Traffic included | __________ |
| Potential coverage | P1/P2 paths that could cross | __________ |
| Blind spots | Paths or directions outside the view | __________ |
| Observed evidence | Authorized packet observations | Leave blank—none supplied |
| Narrow conclusion | Claim supported by scope | __________ |

## 2. Potential visibility

Mark **Yes**, **No**, or **Unknown**, then explain. These are route intersections, not packet findings.

| View | P1 | P2 | Reason or limit |
|---|---|---|---|
| Endpoint A interface | ____ | ____ | __________ |
| TAP on switch–gateway link; both outputs | ____ | ____ | __________ |
| Same breakout TAP; one output only | ____ | ____ | __________ |
| SPAN selections/directions include P1 | ____ | ____ | __________ |
| SPAN excludes Endpoint B’s path | ____ | ____ | __________ |
| Gateway | ____ | ____ | __________ |
| One selected cloud interface | ____ | ____ | __________ |

## 3. Reasoning questions

1. Why can a gateway-only view not resolve P1? Name an authorized source intersecting P1.  
   **Answer:** ______________________________________________

2. For a real capture lacking a visible reply, give narrow wording, three collection explanations, and one SPAN count caution.  
   **Answer:** ______________________________________________

3. For a possible NAT match, list correlation fields and attribution limits.  
   **Answer:** ______________________________________________

4. Cloud extension: record the selected interface, directions, T0–T1, and selection rules. What limits are specific to Amazon VPC Traffic Mirroring?  
   **Answer:** ______________________________________________

5. If an authorized PCAP is later supplied, where would you check its time range, interface information, addresses, and exchanges? Why can a display filter not repair collection scope?  
   **Answer:** ______________________________________________