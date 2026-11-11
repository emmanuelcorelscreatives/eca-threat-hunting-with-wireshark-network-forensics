# Define a Beaconing Hypothesis — Worksheet

This is a blank evidence template. Nothing becomes an observed fact until copied from the selected capture. **Synthetic exercise option:** label work using the DNS fixture as synthetic supplemental practice, never as an incident.

## 1. Evidence source and scope

- Source filename/path: ______________________________________
- Mode: ☐ synthetic DNS supplement ☐ independently authorized capture
- First available packet time: _______________________________
- Last available packet time: ________________________________
- File duration: _____________________________________________
- Capture point/collection details, or unknown: ______________
- Observed directions: _______________________________________
- Known gaps, loss, or missing direction: _____________________
- Clock status when comparing devices: ________________________
- What this coverage cannot establish: ________________________

## 2. Identity and filter

- Host address: __________________ Device: ____________________
- Address-to-device mapping source and validity during window: __________________________________________________________
- External peer address: _____________________________________
- Service name, only if supported: ____________________________
- Evidence supporting peer/service identity: _________________
- Address family: ____________________________________________
- Both-endpoint display filter actually used: _________________
- Both directions visible? ☐ yes ☐ no ☐ unknown. Basis: ______

## 3. Hypothesis and contact rule

During __________________ to __________________, does the mapped host __________________ repeatedly start clearly separate contact with peer/service __________________, warranting investigation?

Protocol evidence required to call an event a new host-started exchange: __________________________________________________

Treatment of responses, retransmissions, and continuations: _____________________________________________________________

Treatment of ambiguous or pre-capture starts: ________________

## 4. Observation log

Schema: `observation_id,frame_references,timestamp,endpoints,direction,protocol,event_classification,certainty,notes`

| Obs. | Frame reference(s) | Timestamp | Endpoints | Direction | Protocol | Classification | Certainty | Notes |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | |
| | | | | | | | | |
| | | | | | | | | |
| | | | | | | | | |
| | | | | | | | | |
| | | | | | | | | |

`frame_references` are source packet numbers. `endpoints` records source → destination. Classification must be `new start`, `response`, `retransmission`, `continuation`, or `uncertain`. Certainty must include a reason.

## 5. I/O Graph review

Graph region(s) used to locate packets: _______________________

Packets reviewed afterward: _________________________________

☐ I did not count graph points as callbacks or calculate inter-arrival timing.

## 6. Alternative and assessment

- Ordinary explanation, such as an approved updater, monitoring agent, or time-synchronization client: _____________________
- Host/service ownership evidence: ___________________________
- Evidence that would support further investigation: _________
- Evidence that would weaken suspicion: ______________________
- Missing evidence or requested authorized context: __________
- Assessment: ☐ supports further investigation ☐ weakens suspicion ☐ remains open
- Capture-bounded reasoning with frame references: ___________

## 7. Practical questions

1. Why is a reply not automatically a fresh outbound contact?

Answer: _____________________________________________________

2. Why can neither a conversation row nor an I/O Graph point be treated as a contact count?

Answer: _____________________________________________________

3. What can a display filter change, and what can it not recover?

Answer: _____________________________________________________

4. Why can regular rhythm identify neither command and control nor the initiating process?

Answer: _____________________________________________________