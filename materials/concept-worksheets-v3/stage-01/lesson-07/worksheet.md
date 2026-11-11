# Your Starting Skills Check

> Draft supporting worksheet; separate review is required. Use only authorized course files in an isolated training environment.

## 1. Route and context

Route: ☐ No diagnostic file ☐ Instructor-supplied authorized file inspected

| Field | Entry |
|---|---|
| Status | |
| File identity | |
| Intended time window | |
| Capture point | |
| Known gaps | |

With no file, enter **Pending** for Status and leave capture entries blank. If supplied context is missing, enter **Unknown**; a filename cannot establish the time window.

## 2. Five prompts

On the no-file route, answer as **hypothetical protocol exercises** and leave packet-specific data blank.

1. **TCP/IP:** Name network-endpoint fields and transport details. What does SYN show, what exchange usually establishes TCP, and what attribution remains unknown?

   ________________________________________________________________

2. **DNS:** Identify query name/type, sender, and any response. Does this prove a later connection? What wider coverage could clarify a missing one?

   ________________________________________________________________

3. **HTTP:** Identify method/target and related response/status. If the response is outside the window, what is known and unknown? What cannot be attributed?

   ________________________________________________________________

4. **TLS:** State what is visible and where protected content begins. Can hidden HTTP content or the initiating process be inferred? Explain.

   ________________________________________________________________

5. **Navigation:** Explain the packet list, selected details, and lower captured bytes. Predict what `tcp`, then `http.request`, changes; interpret no matches narrowly.

   ________________________________________________________________

## 3. Evidence, explanations, and questions

Use actual values only after inspecting an authorized file. A timestamp is capture time, not proof of an unseen host action; missing traffic does not prove absence.

| # | Direct observation | Filter or starting point | Actual frame |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |

Without a file, leave that table **Pending**. Complete the next tables only by labelling each basis **Synthetic exercise** and naming the relevant prompt; never imply that packets were observed.

| Basis | Hypothesis | Plausible alternative | Authorized test/evidence |
|---|---|---|---|
| 1 | | | |
| 2 | | | |

| Unanswered question | Observation, coverage, or authorized record needed | Missing-direction/encryption/capture-point dependency |
|---|---|---|
| 1 | | |
| 2 | | |

## 4. Reasoning check

Mark **S**upported or **U**nsupported. For an unsupported claim, name evidence needed for the stronger conclusion.

| Statement | S/U | Needed evidence |
|---|---|---|
| Addresses are visible; person/process remains unknown. | | |
| SYN alone proves completed TCP and application action. | | |
| A DNS query proves a later connection. | | |
| No `http.request` match proves no web request occurred. | | |
| TLS application content is readable without working decryption material. | | |

Choose refreshers only from revealed gaps.

| Gap/refresher | One small practice action |
|---|---|
| | |
| | |

## Field schema

`protocol`: category; `status`: Pending, Observed, or Unknown; `observation`: visible fact; `filter`: exact filter/start; `frame`: inspected frame only; `hypothesis`: testable explanation; `alternative`: competing explanation; `question`: unresolved issue; `required evidence`: authorized source needed; `refresher`: revealed gap and action.