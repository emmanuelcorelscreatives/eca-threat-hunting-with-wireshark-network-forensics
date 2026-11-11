# Define the Pivots and Stop Conditions — pre-case worksheet

> **Scope:** This is a plan, not a finding. The Project 1 capture and contextual records are not supplied in this lesson. Do not invent hosts, addresses, peers, times, frames, packet results, or conclusions. Leave every case-value and evidence-ledger cell empty.

## Downloads and setup

Required downloadable resources are `worksheet.md` (exercise) and `answer-guide.md` (reasoning and checks). Save a working copy and open it in a text editor or Markdown viewer. No capture or Wireshark installation is needed. Later packet work must use authorized, Academy-supplied synthetic case materials.

## 1. Starting question and alternatives

“Your starting hypothesis is that an identified workstation made outbound contact worth examining. Scheduled software might explain it.”

1. What future observation could support further investigation?  
   **Answer:** ________________________________________________
2. Which trustworthy scheduling or asset record could confirm the activity’s time, owner, and applicability to this workstation?  
   **Answer:** ________________________________________________
3. What missing evidence could leave both explanations unresolved?  
   **Answer:** ________________________________________________

## 2. Future case inventory and coverage

Do not enter values now; this table defines later evidence needs.

| Field | Required meaning | Case value |
| --- | --- | --- |
| Workstation identity | Host or asset identifier and inventory source | |
| IPv4 assignment | Address, assignment source, and assignment period | |
| Reported interval | Start, end, and time basis | |
| Capture | Source filename, capture point, and paths it might miss | |
| Coverage | First/last packet times, surrounding traffic, and gaps—including a capture starting after reported activity | |
| Clock | Accuracy corroboration, if available; a displayed timestamp is not validation | |

## 3. Pivot plan

Work in host, time, protocol, then peer order. Complete only planning cells.

| Pivot and focus | Question, boundary, or narrowing method | Context this could hide | Result that would challenge your preferred explanation |
| --- | --- | --- | --- |
| Host: outbound traffic and replies; justify added hosts | __________________ | __________________ | __________________ |
| Time: reported period and surrounding traffic; use reasoned, not arbitrary, boundaries | __________________ | __________________ | __________________ |
| Protocol: decoded evidence, port ambiguity, encryption, or incomplete exchanges | __________________ | __________________ | __________________ |
| Peer: other contacts in the covered window and who can confirm business purpose | __________________ | __________________ | __________________ |

With an authorized capture and verified case address, plan `ip.addr == <VERIFIED_CASE_IPV4>`; replace the placeholder before use. For IPv4, it matches either endpoint and does not claim packets or peers exist. A display filter narrows the visible view without removing packets; clear it to inspect surrounding traffic. In Statistics > Conversations, start, duration, packet, and byte counts can select candidates, not decide approval or harm. An active display filter can limit its list.

Planned comparison scope—filtered host traffic or broader capture: __________________

## 4. Evidence ledger — leave rows empty in this lesson

| Source file | Displayed timestamp and time basis | Frame | Visible observation | Limited claim | Explanation and corroborating record | Decision or gap |
| --- | --- | --- | --- | --- | --- | --- |
| | | | | | | |

A packet may show an exchange observed at the capture point. Alone, it cannot establish process ownership, a person’s intent, authorization, compromise, or an attack technique. Keep observation, explanation, and decision distinct.

## 5. Stop conditions and next steps

| Outcome | Required basis | Your criterion and matching next step |
| --- | --- | --- |
| Further investigation | Relevant host-to-peer activity in the covered window and a clear reason the routine explanation falls short | Criterion: __________ Next: __________ |
| Weakened suspicion | Trustworthy scheduling or asset records confirm expected activity for this host and time; document remaining limits | Criterion: __________ Next: __________ |
| Unresolved | Missing interval, one-direction visibility, missing host context, or another named gap | Gap: __________ Specific request: __________ |

Never call traffic harmless just because its protocol is common or its destination responds. An empty filtered view cannot prove the activity never happened. No branch needs a universal packet-count rule.

## 6. Self-check

- [ ] Each pivot names a question, hidden context, and challenging result.
- [ ] The ordinary explanation could be disproved, not merely repeated.
- [ ] Filter and Conversations scope are recorded.
- [ ] Every outcome has a criterion and proportionate next step.
- [ ] Case values and ledger rows remain empty.