# Containment Decision Worksheet

**Synthetic supplemental practice:** Do not present this exercise as Project 7 or as a captured incident.

## 1. Evidence boundary

- Original identifier: ____________________ Analysis-copy identifier: ____________________
- Actual hashes of original PCAP and analysis copy (calculate and record both): ______
- Capture point: ____________________ Time window: ______________________________
- Relevant host/conversation: _________________________________________________
- Directions seen: ____________________ Directions missing: _____________________
- Hypothesis being tested: ____________________________________________________
- Packet observations only: ___________________________________________________
- Fictional service-catalog context: ___________________________________________
- Inferences, labelled: _______________________________________________________
- Unknowns and records needed: ________________________________________________

## 2. Compare all three choices

For **each** row address: potentially justifying observation; plausible harmless explanation; confidence limits; coverage and omissions; approver or urgent delegate; implementing team; asset/service owner; evidence to preserve, custodian, and what the action could alter; disruption; cost of waiting; review time; and the observation that would change the recommendation.

| Choice | Decision record |
|---|---|
| Host isolation | ______________________________________________________________ |
| Account limit | ________________________________________________________________ |
| Network block | ________________________________________________________________ |

## 3. Evidence ledger

Use actual values only. Calculate and record each available item's hash, including the original PCAP and analysis copy. Mark supporting records that cannot be obtained as requested or unknown. Leave an unsupplied deadline open.

| Item | Handling time and identifying details | Actual hash (required for available items) | Controlled location | Owner/custodian | Retention deadline |
|---|---|---|---|---|---|
| Original PCAP |  |  |  |  |  |
| Analysis copy |  |  |  |  |  |
| Host records |  |  |  |  |  |
| Identity records |  |  |  |  |  |
| Network records |  |  |  |  |  |

## 4. Practical questions

1. If only a network conversation is known, which account can responsibly be named for suspension?  
   **Answer:** _________________________________________________________________
2. What does peer port 443 establish, and what does it not establish?  
   **Answer:** _________________________________________________________________
3. What does applying and clearing `tcp` change?  
   **Answer:** _________________________________________________________________
4. Why must `SVC-01` be assessed before a broad peer block?  
   **Answer:** _________________________________________________________________

## 5. Incident-lead handoff

Select one: **immediate authorized action / action under stated conditions / urgent evidence request**.

State the observation, affected boundary, confidence, harmless alternative, recommendation and rationale, authorizer, implementer, covered assets, omissions, expected disruption, preservation owners, cost of delay, review time, and reconsideration trigger:

______________________________________________________________________________

______________________________________________________________________________