# Answer guide

**These are source-derived arithmetic controls, not executed software output or case findings.**

1. Every range has 100 positions: `99 - 0 + 1 = 100` for A and B; `159 - 60 + 1 = 100` for C.

2. Observed transmitted TCP payload is `100 + 100 + 100 = 300` bytes. This sum includes repeated positions.

3. A adds 100 positions. B repeats 0–99 and adds 0. C overlaps A at 60–99 and adds 60 positions, 100–159. The union is 0–159, containing 160 distinct positions.

4. Removing B leaves 200 bytes. That is still 40 bytes above 160 because C partly overlaps A at positions 60–99. Removing only a segment identified as a full retransmission does not remove partial overlap.

5. Measurement record:

   - Frame volume: **not computable**; no frame lengths were supplied.
   - Transmitted TCP payload: **300 bytes**, including repeats.
   - Distinct observed sequence positions: **160 bytes**, within this one connection, direction, and window.
   - Application-content measure: **not supported**; no visible or reassembled application evidence was supplied.

6. A Conversations total can include replies, acknowledgments, opposite-direction traffic, overhead, and traffic outside the intended scope. Distinct TCP positions are transport data, not automatically distinct application content: they may include application headers or framing, and repeated content can use new positions. An acknowledgment concerns TCP’s expected position; it does not prove that an application saved a file. None of these measures establishes sensitivity, authorization, or loss.

7. Because no case capture exists, the evidence-template fields should remain blank or say **not available—no case capture**. In an authorized investigation, record actual scope rather than guessing. A late start, missing segments, truncation, one-sided visibility, or encryption limits what can be established.

8. Example: **In this synthetic source-to-peer example, the selected segments contain 300 transmitted TCP payload bytes and occupy 160 distinct sequence positions observed in the stated connection and direction; no frame-volume, application-content, retention, authorization, or data-loss conclusion is supported.**