# Claim Review Worksheet

## Status and purpose

**Synthetic exercise—not a captured incident or observed result.** No Project 7 capture was supplied; this worksheet is an example, not a finding. The published DNS baseline is not an input or evidence for this exercise.

> A report can describe the right packet yet reach the wrong conclusion.
>
> Where does the claim change?
>
> The small leap is from captured communication to a report’s claim about an actor’s purpose.

## Materials and setup

Required downloads: `worksheet.md` and `answer-guide.md`. No capture, software, credentials, or external records are required. Use only the conditional example below. Complete this worksheet before consulting the guide.

## Label and row guide

- **Fact:** What a record shows, limited to its collection and viewing scope.
- **Inference:** A conclusion drawn from evidence.
- **Unknown:** A question the available evidence does not resolve.

These labels do not rank importance. For each row, state the claim, label, basis, limits, credible alternative, and minimum authorized test that could change the assessment. If an alternative to the conditional observation itself or to a process that has not been proposed is not meaningful, write **not applicable** rather than inventing one. For connection presence, checking an authorized capture and its collection and viewing scope, if supplied, would test the observation; do not imply that check occurred.

## Conditional example

If an authorized capture showed an outbound TLS connection—an encrypted connection—the fact is its presence in recorded traffic during the observed window not which application started it.

Review this deliberately weak sentence:

> “The connection proves sensitive data was stolen.”

## Task 1 — Split and label the claims

Do not treat the sentence as one claim.

| Separate claim | Fact, inference, or unknown? | Basis | Evidence/view limit | Credible alternative | Minimum authorized test |
|---|---|---|---|---|---|
| Connection presence | __________ | __________ | __________ | __________ | __________ |
| Investigative relevance | __________ | __________ | __________ | __________ | __________ |
| Proposed purpose or intent | __________ | __________ | __________ | __________ | __________ |
| Process that started it | __________ | __________ | __________ | __________ | __________ |
| Transferred content | __________ | __________ | __________ | __________ | __________ |
| Sensitivity of any data | __________ | __________ | __________ | __________ | __________ |
| Whether data was stolen | __________ | __________ | __________ | __________ | __________ |

## Task 2 — Bound the view

For scenario-specific items, write **not supplied** unless the scenario provides them. State the known general effect of a display filter separately.

- Capture point: ____________________
- Recorded time window: ____________________
- Whether all relevant packets were viewed: ____________________
- Whether a display filter was used (and its settings): ____________________
- General effect of a display filter on the view: ____________________
- Address mapping checked: ____________________
- Cross-system clock alignment checked: ____________________

Rewrite “No related exchange occurred” so it states only what the examined view could support:

__________________________________________________________________

If packet and host-event order depends on different clocks, how should the order be described?

__________________________________________________________________

## Task 3 — Show how confidence could change

Choose the relevance inference from Task 1.

- Result that would raise confidence: ______________________________
- Result that would lower confidence: ______________________________
- What would remain unknown either way: ___________________________
- Authorized case role or person who should request the record: ____________________

Do not assume a requested record exists or will answer every question. No case requester is specified; a generic authorized role or **not supplied** is acceptable.