# Answer Guide: Reasoning Key

This guide scores reasoning from the stated synthetic inputs, not packet findings. Award 10 points.

## Rubric

1. **Evidence status — 2 points:** The contact is **reported**. Scheduled software activity is **hypothetical**. Activity by `SYN-WS-02` is **unknown**. Nothing qualifies as **observed** because no supporting evidence is supplied.

2. **Triage — 1 point:** Questions seek the peer's identity, whether it was expected for `SYN-WS-01`, whether evidence matches the report, and whether authorized schedule context could explain it.

3. **Bounded hunt — 2 points:** A suitable question is: “Did `SYN-WS-02` make a contact comparable to the reported `SYN-WS-01` contact during `2025-02-01 09:00–10:00 UTC`, according to authorized evidence covering `SYN-WS-02` for that period, once enough peer or behavior detail is available?” This proposes a test; it does not claim another contact occurred.

4. **Evidence request — 1 point:** The answer requests authorized evidence that actually covers `SYN-WS-02` and the stated window, plus enough peer or behavior detail to define a match. That evidence is not supplied.

5. **Coverage — 1 point:** A `SYN-WS-01`-only capture cannot settle activity on `SYN-WS-02`. The correct status is **unknown**. “Unknown from this capture” is not an all-clear.

6. **Interpretation — 1 point:** Scheduled activity remains possible but unverified. Packet bytes alone can't establish which process was running, what someone intended or whether a system was compromised.

7. **Decision route — 1 point:** Triage is current. A bounded hunt is appropriate if a meaningful wider question remains after obtaining comparison detail. Incident response is not established by this input. If the organization's incident criteria are met, response comes first.

8. **Handoff — 1 point:** A complete handoff separates the reported lead, proposed search, ordinary alternative, unknowns, and needed evidence. It must not claim maliciousness, compromise, another contact, or a confirmed incident.