# Byte-measurement worksheet

> A large outbound byte count might mean one transfer, repeated transmissions, or mostly overhead.

**Synthetic exercise—not capture evidence.** All rows belong to one TCP connection, one source-to-peer direction, and one illustrative window.

| Segment | First sequence position | Last sequence position | `tcp.len` |
|---|---:|---:|---:|
| A | 0 | 99 | 100 |
| B | 0 | 99 | 100 |
| C | 60 | 159 | 100 |

## Data dictionary

| Field | Meaning |
|---|---|
| Segment | Illustrative label, not a packet number. |
| First/last sequence position | Inclusive positions occupied by TCP data in the stated connection and direction. |
| `tcp.len` | TCP data length; it excludes much protocol overhead but still counts repeated data. |

## Work areas

1. Verify each inclusive range length using `last - first + 1`.

   A: ______  B: ______  C: ______

2. Sum the transmitted TCP payload.

   Calculation: ____________________  Total: ______ bytes

3. Count only positions not already observed when processing A, B, then C.

   A adds: ______  B adds: ______  C adds: ______

   Merged range(s): ____________________  Distinct total: ______ bytes

4. Remove only fully repeated B. What total remains, and how far does it exceed the distinct total?

   Remaining: ______  Residual overcount: ______  Reason: ____________________

5. Complete the measurement record without inventing unavailable values.

   - Selected outbound frame volume: ____________________
   - Observed transmitted TCP payload: ____________________
   - Distinct TCP sequence positions observed: ____________________
   - Supported application-content measure: ____________________

6. Why is a Conversations total not automatically an upload size? Why do distinct TCP positions not establish file size, sensitive content, receiver storage, authorization, or loss? What does an acknowledgment not prove?

   ____________________________________________________________________

   ____________________________________________________________________

7. Blank case-evidence template—there is no case capture for this exercise. Do not insert invented findings.

   - Capture point and observed side: ____________________
   - Collection window: ____________________
   - Display filter: ____________________
   - `Limit to display filter` state: ____________________
   - Direction, endpoints, and translation mapping: ____________________
   - Truncation, missing traffic, or sequence gaps: ____________________
   - Application visibility or encryption limit: ____________________

8. Write one defensible sentence reporting only the supported synthetic measures and limits.

   ____________________________________________________________________