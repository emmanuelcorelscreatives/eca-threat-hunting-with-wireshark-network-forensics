# Investigation worksheet — packet behavior versus approved work

Use the labelled synthetic `practice.pcap` for practice, or your **own authorized offline capture** for a real investigation; never transfer the synthetic case's findings to a historical or live case. Question: during a defined period, did one initiating source contact multiple distinct targets, and does a task that **actually ran with approval** credibly explain the source, targets, ports, and time? Test maintenance and network-fault explanations by the same standards. An inventory role or matching schedule alone does not answer the question.

## 1. Capture and method — establish limits first

- File and provenance; supplied or safely rebuilt copy; capture point **as known**, not inferred from an Ethernet header; packet/interface information and missing path metadata: ____
- Earliest/latest visible packet, question window, displayed time zone and format, UTC conversion if needed, inventory mapping validity: ____
- What network path could this capture see? What path, time, or reply traffic might it miss? Do not interpret silence outside coverage: ____
- Statistics → Endpoints: display-filter state, broader-view comparison, captured addresses, and initiating direction established from frames rather than endpoint membership: ____
- Statistics → Conversations: filter state, candidate pairs, relative start times, durations, captured **frame** counts and bytes. Statistics → I/O Graphs: compared periods and a consistent proposed one-second interval; record what you actually see, not an unperformed GUI result: ____
- SYN-only filter `tcp.flags.syn == 1 && tcp.flags.ack == 0`; how you inspected replies both ways; when you cleared or adjusted the filter and checked its effect on Conversations: ____

## 2. Packet observations — cite actual frames

For **each** candidate, repeat a row for each distinct target/port. Record UTC time and *actual capture frame number* for each attempt and visible reply; use source and destination ports to distinguish exchanges. Compare same-tuple SYNs and **raw** sequence numbers before counting attempts. A relative TCP sequence display may differ. Treat reset, SYN/ACK and ACK as TCP observations, not application or process proof.

| Initiating source → distinct destination | Destination port | SYN frame(s), UTC time, source port, raw sequence | Reply/ACK frame(s) and direction | Retry, response, or coverage qualification |
| --- | --- | --- | --- | --- |
| ____ | ____ | ____ | ____ | ____ |
| ____ | ____ | ____ | ____ | ____ |
| ____ | ____ | ____ | ____ | ____ |

Distinct destinations versus SYN matches: ____. Other visible replies or network errors, and what remains unobserved: ____. TCP payload/application evidence, if any, **actually present**: ____. Do not confuse PCAP file size, captured frame bytes, TCP payload bytes, and transferred file content. Do not claim that a missing request/reply or an empty filtered view proves an event did not occur elsewhere.

## 3. Operational records — never relabel them packet evidence

Cite the **specific CSV row and columns** or the real records you inspected. For each proposed explanation, record time zone, mapped source/role/manager, responsible owner, expected or permitted targets and ports, planned time, actual execution time/status/configured scope where available, and confirmation still needed. `recorded_unconfirmed` is not owner testimony.

| Explanation and record IDs | Source/owner and planned or ticket window | Actual execution or ticket status; configured/expected scope | Agreement with **cited frames** | Mismatch or missing confirmation |
| --- | --- | --- | --- | --- |
| Approved vulnerability-scan job: ____ | ____ | ____ | ____ | ____ |
| Administrator maintaining systems: ____ | ____ | ____ | ____ | ____ |
| Single-peer service/network fault: ____ | ____ | ____ | ____ | ____ |

A job's recorded run and scope are not proof that it generated a particular packet. An administrator's ticket is not proof of an administrator process; retries and an unanswered peer are not proof of a failing service. Test each explanation against source, **distinct** targets, ports, replies, timing, and owner without letting one source's ticket explain a different source's traffic. Ask for job logs and approved target list, host-process/operator evidence, and relevant service/device records: ____.

## 4. Separate decisions and handoff

**Packet-pattern finding** (what visible frames support, including retries, responses, and coverage limits): ____.

**Authorization finding** (what approval and actual job records establish, whether *every* observed target/port fits, and what they cannot attribute): ____.

**Alternative explanations and unresolved disagreement** (including any out-of-scope contact, unconfirmed tickets, missing owner/process records, or partial coverage): ____. If those gaps prevent a verified match, write **inconclusive** rather than approved or adversarial by appearance.

Specific validation question to the responsible team: “Did your approved task run from this asset during this period, and did its target list include these systems?” Follow up on the actual job, source process and responsible operator; a recurring schedule or general assurance is insufficient. For **Build a Discovery Scope Map**, carry forward only checked source → target → port → time → frame details, labelled with their authorization and coverage uncertainties: ____.