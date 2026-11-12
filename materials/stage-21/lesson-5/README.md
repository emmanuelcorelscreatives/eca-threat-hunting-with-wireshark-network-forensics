# Threat Hunting with Wireshark Course
## Stage 21 : Lesson 5 — Verify Containment and Look for Recurrence

This student kit accompanies the exact saved lecture without changing its narration. The lecture's saved case supplies neither a post-action capture nor an action record: no genuine containment result is available for that case. The supplied supplemental files instead provide an explicitly fictional, offline Academy fixture. All packets, addresses, action records, coverage descriptions, owners and other scenario metadata are fictional, not actual incident evidence.

### Learning goal
Test whether comparable communication appears after an approved action on observable paths. Distinguish a request, deployment, rule presence and verified enforcement; distinguish a TCP attempt from an established bidirectional exchange. Report uncertainty to the incident lead rather than declaring eradication.

### Route through the kit
1. Follow setup.md to preserve source files, reconstruct the two separate captures and verify their hashes.
2. Complete worksheet.md using the supplied records and packet evidence.
3. Compare with answer-guide.md; use DATA_DICTIONARY.md to interpret fields and provenance.

All required work is offline and completable with the supplied files. No production access is needed. The existing decoded CSVs and execution.json document actual TShark execution on synthetic packets. All GUI steps in this kit are learner instructions, not executed GUI evidence. No screenshot or native GUI proof is claimed.

### Deliverable
Submit the completed worksheet and a short decision memo naming the action owner, coverage owner, incident lead as decision owner, source capture/frame/time references, ordinary-service alternatives, limits, stopping point and quantified next check. Keep pre and post captures separate: frame 4 in one file is not frame 4 in the other.

Optional transfer: only if separately authorized and an actual saved own-case capture and action record exist, apply this method to working copies of those materials. This kit does not imply that such a capture exists or authorize collection. The next lesson is Project the Lessons into Recovery and Improvement.