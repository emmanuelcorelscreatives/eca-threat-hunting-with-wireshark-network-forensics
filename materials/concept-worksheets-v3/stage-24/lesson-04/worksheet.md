# Defensible Finding Worksheet

## 1. Select the input

- [ ] Actual capstone hypothesis/register
- [ ] **Synthetic exercise—supplemental text only**

**Synthetic exercise (hypothetical, not an incident or observed result):** A review note says a registered capture showed an endpoint communicating with a peer. The original source identity, packet reference, time, capture point, collection coverage, and payload content are unavailable. Approved synchronization is plausible. No endpoint, identity, or approved-work records are supplied. There is no PCAP and no proof of compromise.

Chosen claim: ______________________________

## 2. Evidence register

Enter `unavailable`; never guess.

| Source identity | Reference | Time | Capture point | Coverage | Observed fields | Limits | Claim/status | Open question |
|---|---|---|---|---|---|---|---|---|
| ______ | ______ | ______ | ______ | ______ | ______ | ______ | ______ | ______ |

**Dictionary:** Source identity is the exact capture or record name. Reference is a colleague-locatable packet or record locator. Coverage states window, location, and relevant path visibility. Observed fields list only captured endpoints, ports, timing, direction, or handshake fields. Limits include encryption, missing direction, truncation, drops, and unavailable records. Use one status per claim: `observed within a defined scope`, `suspicious but unconfirmed`, or `inconclusive`.

## 3. Separate the claim

Observation with source/reference: ______________________________

Context from other records: ______________________________

Working inference: ______________________________

Confidence limit or unknown: ______________________________

## 4. Answer four challenges

For each answer, cite the source/reference, name the strongest ordinary alternative, state evidence for or against it, give a claim-specific confidence limit, request the smallest authorized distinguishing record, and rewrite the claim/status.

1. **Attribution:** What do address, time, and available ports support? Is asset mapping separate? Could reassignment, sharing, translation, or an approved service fit?  
   Answer: ______________________________
2. **Encryption:** Which fields are visible? Which server names, certificates, requests, or content are unavailable? Could synchronization or backup fit?  
   Answer: ______________________________
3. **Missing traffic:** What window, location, path, direction, truncation, or drop limits apply? Which conclusion does the gap prevent?  
   Answer: ______________________________
4. **Compromise:** Does the evidence prove a process or command, credential misuse, human operator, successful compromise, or data loss? Which endpoint, identity, approved-work, or content record would distinguish explanations?  
   Answer: ______________________________

## 5. Decision

Rewritten narrow finding: ______________________________

Responsible decision-maker: ______________________________  
Recommended action and timing: ______________________________  
Operational/preservation effect: ______________________________  
Observation showing whether the action helped: ______________________________  
Evidence that would change the recommendation: ______________________________

## 6. Oral defense

State the observation and citation; strongest alternative; unavailable visibility; and next evidence request or response decision. Replace unsupported absolute words such as *always*, *never*, *all*, or *confirmed*.