# Reusable hunt playbook (draft)

**Procedure owner/version:** _____ / _____. Update the version when steps or assumptions change.

**Hypothesis:** Test whether outbound connections repeat as separate connection starts within the available window and whether asset context explains them. Repeated outbound connections are only a hypothetical example, not a packet finding. Needed telemetry includes an authorized capture and available assignment or translation, asset-role, service-ownership, schedule, and suitable endpoint or network records. Record which are unavailable.

**Method:** Set authorized assets, exact start and end, approved capture files, and exclusions before inspection. Preserve the original; open an approved offline copy with File > Open. Statistics > Capture File Properties: record available details and first and last packet times; do not infer the capture point. Document sensor viewpoint, gaps, truncation, missing directions, displayed time format, original timestamps, and any measured offset between clocks.

For a TCP candidate, start with `tcp`. If case-established addresses justify narrowing, use the both-direction template `tcp && ip.addr == <asset_ip> && ip.addr == <peer_ip>`, replacing both placeholders only with case-established values. Record the exact working display filter and check both directions. A display filter changes the view, not the captured packets. Statistics > Conversations: record whether “Limit to display filter” is enabled; review candidate pairs, separate starts, durations, and directional counts. No count is a universal suspicion threshold. Return to the packet list and distinguish separate sessions from packets in one session. If useful, choose Analyze > Follow, then Back and recheck the earlier filter. Without appropriate authorized secrets, treat protected TLS application content as unavailable; do not guess what transferred.

**Preset decisions:** Benign needs a confirming record matching the activity, asset, and window. Escalate cited, unexplained behavior to a response owner with the affected asset, confidence limits, urgency reason, and decision requested—not a claim of confirmed compromise. Unresolved needs an exact gap, the question a requested record could answer, and an evidence owner. Stop with a documented explanation, specific escalation, or owned evidence request.

## Blank completed-case worksheet — not a finding

**Completed-case use:** Only after checking a previous report, bring forward its observation, source references, and evidence limits. Adapt the hypothetical behavior and preset decisions to what that evidence can test; leave unverified fields blank. This draft is not a finished finding.

**Previous report identifier / checked observation:** _____; **source references (file, recorded hash, frame, timestamp, and stream context where available):** _____; **evidence limits:** _____.

**Case-specific observable hypothesis / required telemetry:** _____; **case-specific benign, escalation, and unresolved criteria, including contrary evidence:** _____.

**Approval/assets/role:** _____; **review start/end/exclusions:** _____; **original/working copy/approved files:** _____.

**Per approved source file:** Record available file details and packet-time bounds separately from the review start/end above. Enter a capture point only if documented; record coverage gaps, truncation, missing directions, the displayed time format, original timestamp information, and any measured clock offset. Add a row for each file.

| Source file; recorded hash | Available file details | Documented capture point | First / last packet times | Gaps / truncation / missing directions | Displayed format / original timestamps / measured offset |
|---|---|---|---|---|---|
| _____ | _____ | _____ | _____ | _____ | _____ |

**Exact working filter/both directions checked:** _____; **Conversations setting/starts/durations/directional counts:** _____.

**Evidence dictionary:** A reference needs source file, recorded hash (digital fingerprint), frame number, packet timestamp, and stream context. Blank means unknown, not absent. Keep observation separate from interpretation.

| Source file; hash; frame; time | Direction; both endpoints; available ports; protocol; stream | Packet observation | Interpretation | Alternative | Context record checked and result | Missing evidence or question |
|---|---|---|---|---|---|---|
| _____ | _____ | _____ | _____ | _____ | _____ | _____ |

**Questions:** What supports distinct starts rather than a packet count? _____ Which replies and sensor limits affect interpretation? _____ Which same-asset, same-window updates, monitoring, backups, authorized administration, or misconfiguration checks remain? _____

**Decision/stop:** benign, escalate, or unresolved _____; supporting or contrary record _____; confidence limits _____; affected asset and urgency reason _____; response or evidence owner _____; question or requested decision _____.

**Synthetic exercise — conditional situations, not observed cases:** A: an approved schedule and owner match the same asset and time. B: referenced separate starts on a sensitive asset remain unexplained, and evidence may expire. C: a traffic direction and asset assignment are unavailable. For each, write a possible outcome _____, confirming or contrary record _____, and gap, owner, and stopping point _____.