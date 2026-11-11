# Compare Like-for-Like Baselines — Worksheet

**Evidence status:** Blank template. No capture, device inventory, schedule, frame reference, or finding was supplied. Do not invent entries. If a role or collection point is unknown, do not equate the files.

**Role key:** A gateway links networks; an endpoint is one device; a resolver handles name lookups rather than workstation tasks.

**Hypothesis:** the conversation differs from comparable traffic.

Weakening explanations: ________________________________________________

## 1. Scope and Period

| Record | File A | File B | Match or limitation |
|---|---|---|---|
| Working-copy filename | __________ | __________ | __________ |
| Collection point | __________ | __________ | __________ |
| Host/device role | __________ | __________ | __________ |
| Stated collection scope | __________ | __________ | __________ |
| First packet, last packet, duration | __________ | __________ | __________ |
| Weekday; working, overnight, or maintenance period | __________ | __________ | __________ |
| Displayed time zone and clock uncertainty | __________ | __________ | __________ |
| Active display filter | __________ | __________ | __________ |

Matched shared period: _________________________________________________

Missing business or maintenance period: ________________________________

Why the periods are comparable—or cannot be compared: _________________

## 2. Match Wireshark Settings

| View | Settings to record | File A | File B |
|---|---|---|---|
| Capture File Properties | Captured versus displayed statistics | ______ | ______ |
| Endpoints | Same IP, TCP, or UDP tab; exact filter; **Limit to display filter** state | ______ | ______ |
| Conversations | Same type, filter limit, and start-time display | ______ | ______ |
| I/O Graphs | Same interval, filter, measure, and time-of-day or capture-relative axis | ______ | ______ |

Candidate conversation or peer: _______________________________________

Start, duration, and directional packets/bytes: ________________________

Representative frame references, only if examined: ____________________

What the available packets show: ______________________________________

## 3. Context and Outcome

Operational record and whether it is planned or verified: ______________

Do host, time, role, and expected peer agree? __________________________

What the record shows: ________________________________________________

Linking inference: ____________________________________________________

Competing explanation: ________________________________________________

Missing evidence or coverage: _________________________________________

Outcome — explained, surviving lead, or unresolved: ____________________

Shortlist entry: conversation ______; matched role ______; hours ______; collection scope ______; statistic/filter ______; limitation ______.

## 4. Synthetic Reasoning Exercises

These are fictional questions, not captured incidents or observed results.

1. A workstation's working-morning file is compared with its quiet overnight file. The overnight total is lower. Is that difference meaningful, and what should change?

Answer: _______________________________________________________________

2. File A uses the UDP Endpoints tab with filter limiting active. File B uses the IP tab without limiting. What must happen before totals are compared?

Answer: _______________________________________________________________

3. A large transfer overlaps a planned backup, but execution and authorization records are absent. What wording is justified, and what evidence is missing?

Answer: _______________________________________________________________

4. Two graphs use capture-relative time although the files started at different clock times. The baseline also omits the candidate period. State the result and next step.

Answer: _______________________________________________________________