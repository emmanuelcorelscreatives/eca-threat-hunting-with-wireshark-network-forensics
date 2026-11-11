# Technical Investigation Narrative Worksheet

> A correct finding is useless if the next analyst cannot trace how you reached it.

**Practice status:** Project 7's capture and supporting records are not supplied. This worksheet records no case finding. Enter verified values only. Use `Unavailable—not supplied` for an absent input and `Unknown—[reason]` when evidence cannot answer. Do not infer a physical observation point from interface metadata or clock accuracy from displayed precision.

## 1. Question and Scope

- Investigation question: ________________________________________________
- Hypothesis or proposed explanation: ____________________________________
- Decision at stake: _____________________________________________________
- Authorized assets: _____________________________________________________
- Examined capture intervals: ____________________________________________
- Documented observation points: _________________________________________
- Uncollected periods, directions or segments: ____________________________
- Time convention and retained source times: ______________________________
- Known clock uncertainty: _______________________________________________

## 2. Evidence Register and Schema

| Kind | Recorded identifier | Recorded hash | Relationship or role | Available interval/direction | Clock/provenance note |
|---|---|---|---|---|---|
| Original capture |  |  |  |  |  |
| Working copy |  |  |  |  |  |
| Supporting record |  |  |  |  |  |

| Claim label | Viewed file/frame | Original source ID/hash/frame | Source timestamp | Stream context | Exact display filter | Limitation |
|---|---|---|---|---|---|---|
| Observation / Inference / Unknown |  |  |  |  |  |  |

**Schema:** Kind separates originals, copies and supporting records. Relationship identifies a copy's source. Enter a recorded hash exactly or mark it missing. Every frame is file-specific; identify working-copy and original references separately. Retain source times and state the narrative convention. Stream context identifies relevant peers or direction. Exact display filter means the literal expression actually used. A limitation states what the evidence prevents you concluding.

## 3. Inspection Trail

- Source opened in Wireshark: ____________________________________________
- Actual filters in order: _______________________________________________
- Purpose and exclusions: ________________________________________________
- Pivot and reason: ______________________________________________________
- Surrounding-traffic recheck: ___________________________________________

A display filter hides nonmatching packets; it does not delete them.

## 4. Finding Paragraph

Copy this block for each claim and arrange verified findings in time order; do not fill gaps.

- Claim label: ___________________________________________________________
- Observation—what the source shows: _____________________________________
- Citation—source/hash/frame/time/context: ________________________________
- Why it matters to the hypothesis: ______________________________________
- Inference—what it may mean: ____________________________________________
- Unknown or stronger claim not established: _____________________________
- Ordinary-business alternative: _________________________________________
- Evidence supporting or weakening each explanation: _____________________
- Ruled-out lead—initial relevance, verified context and scope effect: _____
- Confidence—independent support, conflict or missing evidence: ___________
- Adjacent limitation and effect: ________________________________________
- Transfer wording, only if verified—direction, timing, byte measure and what it measures: __________________________________________________________
- Content or data-loss claim not established: _____________________________

Do not equate conversation bytes with unique sensitive data removed.

## 5. Systems and Limitations

| Group | Systems | Evidence-based reason |
|---|---|---|
| Observed |  |  |
| Potentially affected |  |  |
| Could not assess |  |  |

| Limitation type | Applies? | Conclusion prevented |
|---|---|---|
| Capture gap |  |  |
| Missing direction |  |  |
| Encryption |  |  |
| Unverified asset mapping |  |  |
| Other |  |  |

## 6. Specific Next Request

- Unresolved claim: ______________________________________________________
- Exact endpoint or identity record and time window: ______________________
- Recipient, if known: ___________________________________________________

## Tasks

1. State the question and scope without asserting Project 7 observations.
2. Mark every unavailable source detail; invent no hash, frame, time, filter or mapping.
3. Draft one conditional finding with all three claim labels and an ordinary-business alternative.
4. Complete the review below.

## Reviewer Check

- [ ] The question precedes findings and scope names visibility gaps.
- [ ] Originals, copies and supporting records are separate.
- [ ] Every claim has an adjacent source, filter and reference or is explicitly unresolved.
- [ ] Observation, inference and unknown are distinct; no gap is filled.
- [ ] Alternative, confidence and system-group reasoning match the evidence.
- [ ] Each limitation states its impact and the next request is specific.
