# Project 7 investigation worksheet

Use the supplied separate synthetic case, not unseen original incident evidence. Keep observations, source-derived asset labels, and inferred causal links distinct. Every packet claim must identify its original filename and frame. Every host/business claim must identify a numbered record. Never cite a GUI screenshot alone when an original frame is available.

| Stage/issue | File:frame or record | Original UTC/time basis | Verified correction and proof | Observation / inference / alternative |
|---|---|---|---|---|
| Provenance and coverage | | | | |
| Delivery | | | | |
| Recurring external contact | | | | |
| Internal access | | | | |
| Later outbound activity | | | | |
| Harmless lead | | | | |
| Collection gap | | | | |
| Proposed causal links | | | | |

1. Compare both File Properties views with the manifest. Record first/last packets, observation points, count, format and time basis. Mark the declared gap and whether another source overlaps it. Separate coverage intervals from first/last packet timestamps.
2. On the edge working copy enter `http.request`. Identify the delivery GET and response. Select a packet of that stream and use Analyze → Follow → TCP Stream. Inspect visible request, response and harmless body; record whether any redirect actually appears. Close the Follow dialog, clear any added stream filter, and return to original frame timing/direction. What reached the observation point? Does H1 independently show execution?
3. Apply `ip.addr == 192.0.2.10`, based on I1's valid interval. Open Statistics → Conversations and choose IPv4 or TCP as appropriate; record the selected tab. Decide whether Limit to display filter is enabled before comparing results. Compare peers, start times, duration, direction and byte units, then return to source packets.
4. Distinguish separate connection starts from packets within one session. Use `ip.addr == 203.0.113.30 && tcp.flags.syn == 1 && tcp.flags.ack == 0`. Compute start deltas. Compare B1 and H2. Does installed software inventory actually bind a PID to any socket? Give an alternative to malicious callback.
5. Open the internal working copy. Apply `ip.addr == 192.0.2.10`. Inspect its replied-to peer, TCP handshake and SSH banners in packet details. Cite original frames and I1/I3. Compare B4. State what this does and does not establish about access, authorization, authentication, execution or movement. Do not equate visible order with causation.
6. Return to the edge copy. Inspect `tcp.stream == 5`, the initiator, each direction and visible HTTP POST. Compare conversation frame bytes, TCP payload and HTTP body length as different quantities. State what the records can establish about content and sensitivity; use H4/B3 and identify a decisive missing record. Compare the backup's asset role, peer, time, H3 and B2 before excluding it as an unrelated lead.
7. Submit a preliminary timeline, with original observations on separate lines from inferred links. Include the collection gap, a tested harmless explanation, exact indicators to check, observed assets versus possibly affected assets, and a source appendix. For every unproven link propose a particular endpoint/proxy/storage record that could test it. Stop short of an unsupported incident verdict.

Deliverable: a one-page account plus completed table and source appendix. All four observed relationships may be reported even when their causal links remain unresolved. No learner-owned live capture is required or claimed by this worked practice.
