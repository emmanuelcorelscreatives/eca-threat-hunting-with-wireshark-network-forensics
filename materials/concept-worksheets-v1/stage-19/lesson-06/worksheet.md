# Data-Loss Confidence Worksheet

Complete Part A with an authorized offline capture, or complete both packet-free synthetic exercises. Do not infer missing facts.

## Part A — Blank evidence assessment

### 1. Scope
- Capture reference: ____________________
- Capture point: ____________________
- Time window: ____________________
- Gaps or incomplete coverage: ____________________
- Directions available: ____________________
- Local asset: ____________________
- External peer: ____________________

### 2. Observation and measurement
- What the capture shows going outbound: ______________________________
- Exact counter: __________ Value: ______ Units: ______ Direction: ______
- Counter meaning: ☐ frame bytes ☐ TCP payload ☐ other: __________
- Measurement scope: ____________________
- Limitation and the claim it weakens: ______________________________
- Distinct-content estimate: ☐ unsupported ☐ supported
- If supported, method and limits: _________________________________
- Exactly visible content, or why content is unknown: _______________

### 3. Separate the claims

| Claim | Confidence words | Evidence | Uncertainty or unsupported implication |
|---|---|---|---|
| Outbound traffic | ___ | ___ | ___ |
| Measured volume | ___ | ___ | ___ |
| Distinct content | ___ | ___ | ___ |
| Content identity | ___ | ___ | ___ |
| Sensitivity | ___ | ___ | ___ |
| Transfer authorization | ___ | ___ | ___ |
| Application storage | ___ | ___ | ___ |
| Unauthorized data loss | ___ | ___ | ___ |

### 4. Decision and handoff
- Strongest plausible authorized explanation: ________________________
- Most important blocking question: _________________________________
- Smallest evidence request and why: _________________________________
- Matching known asset/time window: _________________________________

1. Observed outbound activity: ______________________________________
2. Named volume measure and uncertainty: _____________________________
3. Visible content only: ____________________________________________
4. Data-loss confidence and reason: _________________________________
5. Specific corroboration request: __________________________________

## Part B — Synthetic exercises

### S1: Encrypted session
**SYNTHETIC—NOT PACKET-DERIVED.** Declared facts: an authorized capture shows an outbound encrypted session but no readable upload content. No named counter, complete scope, content classification, transfer authorization, or storage evidence is supplied.

Draft the five handoff lines: _________________________________________

Which source would best answer whether classified material was involved? __________

### S2: Partially readable session
**SYNTHETIC—NOT PACKET-DERIVED.** A limited portion of an outbound stream displays `record_type=customer`; the remainder is unavailable. Coverage, distinct-content volume, independent classification, authorization, and storage are unestablished.

Write the narrowest supportable content claim: _______________________

What cannot be concluded from that field? ___________________________

Match each gap to one source: classification; transaction/destination context; object storage; process activity. Sources: DLP finding, proxy details, service upload/audit record, endpoint activity.

Answers: ____________________________________________________________