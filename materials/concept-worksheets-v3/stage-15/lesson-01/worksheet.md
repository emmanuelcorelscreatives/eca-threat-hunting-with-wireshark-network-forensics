# Define the Channel and the Observable Claim — Worksheet

No case packet file is supplied. The synthetic exercises require no capture. Use the blank log only for a separate authorized capture or the optional synthetic fixture; never present a hypothetical as an observed finding.

## Collection record (only if inspecting packets)

Capture name: ____________________

Collection point; basis for endpoint or resolver attribution: ____________________

Covered time window: ____________________

Missing direction, short window, packet loss, or encrypted-content limits: ____________________

## Blank observation log

Choose File then Open and select only an authorized capture. Apply `dns`, then clear it to restore context. Use `dns.flags.response == 0` for questions and `dns.flags.response == 1` for replies. Pair a reply only when its DNS ID, endpoints, question, and transaction context support the match—not because rows are adjacent.

| Frame reference | Time | Direction | Source → destination | DNS ID | Question name / type | Response code / visible answer | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| | | | | | | | |

**Data dictionary:** Frame reference and time identify where and when a packet appears in *your* capture. Direction says question toward resolver or reply toward requester, as visible at the collection point. Source → destination records packet endpoints, not necessarily the original requesting device. DNS ID helps test a question–reply match but is insufficient alone. Question name / type records requested fields. Response code / visible answer records only reply fields actually readable. Status is **Observed** (visible packet fact), **Inferred** (possible interpretation), or **Unknown** (not established); do not put a theory in an Observed entry.

## Questions — synthetic exercises, not captured incidents

**A.** Hypothetically, between an endpoint and its resolver, questions recur and some replies match. A name looks encoded. No meaningful instruction or link to a file or application is available. Write one bounded claim and separate **Observed**, **Inferred**, and **Unknown**. Test ordinary lookup, retry, health check, command exchange, and data transfer. Name the smallest next source for the claim you most need to test.

Claim: ____________________

Observed: ____________________

Inferred / competing explanations: ____________________

Unknown / next source and question it answers: ____________________

**B.** Hypothetically, a collection beyond a recursive resolver includes outward questions but not the incoming direction. Separately, an encrypted connection reveals no DNS contents. Can either view identify an originating workstation or establish that no reply occurred? What additional source would address each limit?

Answer: ____________________

**If using packets:** What do question fields establish? What does a matched reply add? What remains unproven about commands or exposure?

Answer: ____________________