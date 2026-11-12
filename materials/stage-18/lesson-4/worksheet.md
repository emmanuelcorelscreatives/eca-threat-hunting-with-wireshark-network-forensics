# Worksheet — test the possible link through B

**Hypotheses:** A contacted B before B contacted C; activity on B might link the contacts. Competing explanation: B independently ran approved deployment job DEPLOY-42. Timing alone identifies neither cause nor operator. The two supplied separate PCAPs support the packet tasks.

1. From `capture_inventory.csv`, make **two provenance rows**, one per capture: file/ID, modeled location, UTC window, covered and excluded link, collection gaps, capture filter, time basis, clock-offset status, and your Wireshark display filter. Explain why silence about an excluded link proves nothing. Were the clocks physically compared?
2. Check `address_assignments.csv` at each proposed connection time. Are A=`192.0.2.10`, B=`192.0.2.20`, and C=`192.0.2.30` valid labels then? State what you would do if a mapping period were missing.
3. Open each supplied PCAP and check Conversations in **each file**, noting its active display filter and whether Conversations is limited to that filter. Compare start, duration, packet and byte figures, then inspect candidate packets. Use `ip.addr == 192.0.2.20` and each two-address filter from setup. Do not mistake TCP/2222 for decoded protocol or login evidence.

| Proposed edge | Capture and checked frames, both directions | Start, duration, counts and displayed byte basis | Attempt, bidirectional traffic, or stronger evidence? |
|---|---|---|---|
| A–B | | | |
| B–C | | | |

4. Write **one packet-backed sentence per edge**, citing `capture_id:frame_number`. Verify each frame citation against its named file. A Flow Graph can help check order, not supply missing packets.
5. Cite H-B-1, H-B-2, H-B-3, I-AB, I-BC, and M-42 from the synthetic records. For each, say which *specific* session, process, reported outcome, or approved-work claim it addresses. Compare the scheduled-job prediction with a proposed A-through-B cause: account, process parent/job, hosts, service clue, and time. Does M-42 cover A–B? Can either account name identify a human?
6. Draw two **solid packet-supported edges** only after checking their frames. Draw the causal continuation through B as **dotted**. Write a separate, qualified chain sentence. Name counterevidence—including a job trigger, a confirmed different account, or a clock-corrected timing mismatch—and one focused request for B’s session/process or scheduler records in the limited window.

Scope only supported relationships; carry the unresolved causal question into the next lesson, Project 6: The Internal Hop, without treating this exercise as its case.