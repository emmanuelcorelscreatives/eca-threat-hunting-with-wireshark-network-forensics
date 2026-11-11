# Answer guide and reasoning key

No fixed values are available. A correct response leaves evidence fields blank and parameters unresolved unless supported by the learner's authorized observation. This key does not assert that any event was captured.

## Checkable rubric

Award one point for each requirement:

1. **Evidence boundary:** Records packet-supported behavior, scope, references, mapped endpoints, and unknowns without claiming cause or malicious purpose.
2. **Observable source:** Names a repeatable connection-record source and assesses path, time, translation, mapping, and field-semantic coverage.
3. **Correct measurement:** Groups by mapped asset, responder, protocol, and window; counts distinct connection identifiers; sorts starts for adjacent-gap comparison; documents included connection kinds.
4. **Defensible parameters:** Leaves the window, minimum count, interval range, and required matching-gap count unresolved unless evidence supports them.
5. **Decision paths:** Requires verified ownership, asset, peer, and schedule for exclusion. Missing telemetry or mapping produces `UNEVALUABLE`, not `NEGATIVE`.
6. **Investigation output:** Returns asset, peer, window, distinct count, relevant gaps, supporting identifiers, exclusions, and coverage or attribution limits.

**Expected result:** A passing proposal earns 6/6 and remains an investigation candidate, not a deployed detection. Reject any invented number, packet or retransmission count used as a connection count, unsupported malicious conclusion, evidence-free suppression, or claimed implementation or test result.

## Why these checks matter

A display filter changes the captured packets shown; it does not provide continuous collection. Connection records summarize what their sensor observed. Distinct identifiers represent separate recorded connections, while one long-lived connection may contain many packets. Asset mapping is needed to define outbound behavior. Metadata cannot identify the initiating process, user, purpose, or encrypted content. Preserving source identifiers and limits lets an analyst investigate without overstating what the candidate proves.