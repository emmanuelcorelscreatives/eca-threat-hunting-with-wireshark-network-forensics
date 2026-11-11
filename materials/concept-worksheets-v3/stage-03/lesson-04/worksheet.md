# UTC Comparison Worksheet

Name: ____________________  Date: ____________________

Complete one record per source. Do not replace source wording with analysis.

## Reusable source record and data dictionary

| Field | Meaning | Answer |
|---|---|---|
| Evidence status | Narration hypothetical, supplemental synthetic, or unresolved | __________________ |
| Source reference | Log identifier or capture identity | __________________ |
| Original timestamp | Exact source wording | __________________ |
| Offset/zone and provenance | Recorded value or name, and where it appeared | __________________ |
| UTC value | Conversion, or `unresolved` if its basis is unknown | __________________ |
| Recorded precision | Source-recorded time granularity | __________________ |
| Packet locator | `frame.number`; blank without a capture | __________________ |
| Clock measurement | Device, reference, comparison time, difference, and uncertainty | __________________ |
| Corrected time or interval | Only when supported by a relevant measurement | __________________ |
| Order assessment | Supported, correction-dependent, or inconclusive; explain | __________________ |

## A. Narration hypotheticals

1. Preserve this source wording:

> October seventh, twenty twenty-six, at fifteen twenty, with a recorded offset of plus three hours.

Calculation: ______________________________  
UTC equivalent: __________________________  
Recorded precision: ______________________

2. The hypothetical packet was reported at **twelve twenty and four seconds UTC**. Compare it with the illustrative log time of exactly 12:20 UTC.

Uncorrected order and difference: ________________________________________

Conditional only: an independent measurement shows the capture clock was five seconds fast at that time. Show the correction and resulting order:

________________________________________________________________________

What measurement details would a real correction require? _______________

3. May that correction automatically be applied throughout a capture? Why?

________________________________________________________________________

4. What do a trailing `Z` and six visible fractional digits establish? Do either prove clock accuracy?

________________________________________________________________________

## B. Supplemental synthetic exercises

**N1 — fictional uncertainty exercise, not capture evidence:** A packet is reported at 12:20:04 UTC. A relevant fictional measurement says its clock was fast by 5 ±2 seconds. Calculate the corrected interval and compare it with exactly 12:20:00 UTC.

Interval: __________________  Order assessment: __________________________

**U1 — unknown zone:** A log says fifteen twenty but gives no offset or zone. Record its UTC instant and list what must be investigated.

________________________________________________________________________

**U2 — repeated local time:** During a backward clock change, a named-zone local reading occurs twice and has no numeric offset. What could distinguish the two instants?

________________________________________________________________________

## C. Packet-observation evidence template

No capture is supplied; do not complete this from imagination.

Existing display format: __________________  Capture identity: ______________

`frame.number`: __________________  `frame.time_utc`: ______________________

Final qualified conclusion: _____________________________________________