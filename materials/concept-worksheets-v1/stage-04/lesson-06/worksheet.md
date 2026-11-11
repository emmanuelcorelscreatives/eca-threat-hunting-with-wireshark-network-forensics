# Project 1 Debrief Worksheet

Use `SYN-NAN-001` only as context. Leave unsupported packet fields blank and document each gap separately.

## 1. Bounded question

**Does approved software activity explain this workstation's unexpected outbound session in the defined window?**

Host: ______  Start: ______  End: ______  Time zone: ______  
Behavior tested: ______  Approved-activity alternative: ______

## 2. Evidence scope

Source capture: ______  Authorization reference: ______  
Observation point: ______  Recording window: ______  
Visible directions: ______  Clock basis/uncertainty: ______  
Known gaps: ______  Original/working-copy separation: ______  
Unavailable capture or manifest explanation: ______

## 3. Observation register

**Schema:** Citation/details means source capture, authorization, observation point, displayed timestamp, time basis/clock uncertainty, original frame, endpoints, protocol, exact details, Wireshark pivot, and broader-view restoration. Observation means a visible network fact. Attribution is a separately supported cause claim. Gap/status is required when unsupported; allowed status is `packet-backed` or `not supplied`. Frames are positive capture-local integers.

| ID | Evidence role | Citation/details | Observation | Attribution | Gap/status |
|---|---|---|---|---|---|
| O1 | Establish connection | ______ | ______ | ______ | ______ |
| O2 | Test timing against approved activity | ______ | ______ | ______ | ______ |
| O3 | Examine surrounding exchange | ______ | ______ | ______ | ______ |

## 4. Competing explanations

| Explanation | Support | Contradictions | Missing context |
|---|---|---|---|
| Suspicious activity | ______ | ______ | ______ |
| Approved activity (`SYN-NAN-001`) | ______ | ______ | ______ |

Does the note cover this host? ______ Time? ______ Connection type? ______  
Could clock uncertainty alter the comparison? ______  
What remains unexplained? ______

## 5. Decision

Leave these unselected unless evidence meets the condition:

- [ ] **Supported:** packets meet the limited suspicious claim; approved activity does not account for them.
- [ ] **Unsupported:** observations weaken suspicion after a fair, covered comparison.
- [ ] **Inconclusive:** a confirmed event remains, but a named gap prevents distinction.

Current source-limited status: ______  
Confidence and its scope: ______  Relevant limit: ______  
Confirmed packet-backed event: ______  
Explanations not distinguishable: ______  
Evidence that could change the decision: ______

## 6. Next action and handoff

Recipient/team: ______  Subject host: ______  
Bounded start/end/time zone: ______  Connection details, if available: ______  
Request connection-to-process records for that window, **if they exist**. Record availability, source, timestamp basis, process identity, owner, or approved schedule: ______  
Has any comparison occurred? ______

**Which outbound sessions from this workstation remain unexplained after you account for approved activity in the same window?**

Host scope: ______  Time boundary: ______  Required evidence: ______  
Harmless activity to compare: ______  Stop condition: ______

Handoff status/confidence: ______  
O1: ______  O2: ______  O3: ______  
Alternative tested: ______  Limits: ______  Next owner/action: ______  
End with the reusable question: ______