# Controlled Collection Worksheet

All A01–A06 cases are synthetic thought exercises—not captures, incidents, permission, or observed results. Use only stated facts; omitted facts are unknown.

## Decisions

**Synthetic A01 — Bounded plan.** A fictional owner approved one lab-facing segment and short window. Route and ownership match its paper map; every checkbox was reviewed and only the confirmed lab-facing interface is selected. The approved local location has sufficient space and suitable access. Proposed name: `lab-window.pcapng`. Stop: automatically after 60 seconds, or earlier if approval changes. An empty capture filter is approved for all segment-visible traffic. Retention is limited to the fictional exercise. Hypothesis: could this point show an approved request to a local training service, if available? No endpoint is supplied; nothing was collected.

1. May this plan proceed within the scenario? Name three continuing bounds.
2. What may be recorded only after collection?

Answer:  
__________________________________________________________________  
__________________________________________________________________

**Synthetic A02 — Ambiguous scope.** The highlighted interface has a familiar name, but its route and ownership were not confirmed. A second interface is also checked.

3. Start or stop? Why do the name, highlight, and Start button not resolve scope?

Answer:  
__________________________________________________________________

**Synthetic A03 — Narrow policy.** All A01 checks except filter choice pass. Policy requires capture filter `tcp`, and the question concerns a TCP exchange. UDP or address-resolution context might later matter.

4. What does `tcp` retain and omit? May the learner clear it for context? What must the note disclose?

Answer:  
__________________________________________________________________  
__________________________________________________________________

**Synthetic A04 — Unavailable service.** The optional local training service is unavailable, and no capture has started.

5. What should the learner do, and what result may be claimed?

Answer:  
__________________________________________________________________

**Synthetic A05 — Rotation.** A longer collection switches files every five minutes, keeps three, spans illustrative intervals I1–I4, and has no separate stop condition.

6. After I4, which intervals remain? Has capture stopped? Give one interpretation risk.

Answer:  
__________________________________________________________________

**Synthetic A06 — Filters.** A display filter may hide saved packets. The collection-time capture filter is unknown, and no relevant frames are currently visible.

7. What can clearing the display filter restore? What cannot it restore? What conclusion follows?

Answer:  
__________________________________________________________________

## Collection Note

Complete this from A01. Mark items as planned, observed, unknown, or not applicable; never convert expectations into findings.

- Hypothesis: ______________________________________________
- Approval, segment, and observation point: __________________
- Proposed filename / actual file status: ____________________
- Capture filter, included scope, and omissions: ______________
- Permitted duration / actual start and stop: _________________
- Optional request attempted or skipped: _____________________
- Observed frames, source file, and endpoints: _______________
- Retention: ________________________________________________
- Missing-traffic alternatives and next check: _______________