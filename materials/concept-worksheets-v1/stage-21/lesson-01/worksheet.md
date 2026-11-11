# Response handoff worksheet

**Synthetic exercise only.** The note below is fictional. It is not a captured incident, packet evidence for this lesson, or a finding from Project 7.

**Resources and setup:** Provide this worksheet and `answer-guide.md` as downloadable Markdown files. Open this file in a text editor or Markdown viewer, complete the blanks, then compare your answers with the guide. No capture, Wireshark installation, shared dataset, or other input is required.

**Field definitions:** A *reported observation* is what a note claims, not a verified packet finding. An *inference* interprets a claim. An *unknown* is not established. A *possible harmless explanation* needs checking against business context. A *coverage gap* is time or a path the stated capture cannot address.

## Synthetic hunt note

No original capture, packet references, or interval endpoints are supplied.

- **S1:** The fictional note reports traffic between a service host and an unfamiliar external peer at a service-egress capture point during a review interval.
- **S2:** This proves the host is compromised.
- **S3:** Approved software activity could explain the traffic.
- **S4:** The note reports a gap within the interval and no visibility into other network paths.
- **S5:** Activity during the gap, the initiating process, authorization, and exchanged contents are unknown.
- **S6:** The service owner, service importance, evidence-retention deadline, and disruptive-action approval path are not provided.

## Questions

1. Classify **each** statement as reported observation, inference, unknown, or possible harmless explanation. Why is S2 different from S1?

| Statement | Classification | Reason |
|---|---|---|
| S1 |  |  |
| S2 |  |  |
| S3 |  |  |
| S4 |  |  |
| S5 |  |  |
| S6 |  |  |

2. Bound the lead. Which asset, peer, capture point, and time span are stated? What details and paths remain unobserved?

**Scope:** ________________________________________________

**Limits:** _______________________________________________

3. Draft a handoff **without declaring an incident**. State the triage question, what would change the decision, a harmless alternative, who decides, and whether you recommend further analysis, immediate action, or closure. Address preservation, possible service disruption, and required approval.

**Handoff:** ______________________________________________

___________________________________________________________

4. If an action is authorized, how would you separately check its intended effect and service usability? What would you still be unable to conclude? Name an improvement role and a review point.

**Checks and limits:** _____________________________________

**Improvement and review:** _______________________________