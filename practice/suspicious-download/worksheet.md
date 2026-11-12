# Investigation worksheet

**Hypothesis:** the visible redirect delivered `review.txt` to the mapped client; a separate question is whether that workstation saved or executed it. Work only from the supplied verified practice capture and labelled scenario excerpt. Fill worksheet frame cells only after your own inspection; never transplant these entries into the unavailable lecture case.

1. Record capture point and directions, PCAP time bounds, client/device mapping, both sources' original timestamp bases, measured offset **if supplied**, endpoint event categories and completeness. Check the full packet list before filtering. If the client is absent, revisit scope and mapping.
2. For each `http.request`, record PCAP filename, actual frame/time, source/destination, method, Host and path. For each `http.response`, record matching conversation, actual frame/time, status, declared type, Location, body visibility and any missing bytes. Test a later request against each redirect; mark an absent hop **unobserved**. A Referer, if present, does not independently prove why the first page opened.
3. Timeline columns: source | original reference | timestamp and zone | request/reply or host event | observed detail | inferred link | alternative/gap. Include the control exchange and its event references.
4. Artifact register columns: network object | response frames | declared length/type | captured/reconstructed bytes | analyst-export filename/size/hash **after verification** | endpoint event/path | limitation. Do not equate an analyst export with a workstation file.
5. Assess separately: **response at capture point**, **host save**, **execution of the proposed object**. For each give supporting source references, conclusion, confidence, alternative explanation and targeted next request. Compare the updater control using identical tests. A nearby process is not automatically the downloaded object's execution. State whether process collection could have observed the event; missing entries in an incomplete excerpt are not proof of non-execution.

Deliver the cited timeline, artifact register and initial-access assessment. Ask specifically for bounded file-activity records, process-collection details or the missing capture/web perspective where each would resolve a gap.

Use investigation-workbook.ods for the same Timeline, Artifacts, Assessments and Scope fields. A PENDING template cell is intentional space for your own source-cited answer.
