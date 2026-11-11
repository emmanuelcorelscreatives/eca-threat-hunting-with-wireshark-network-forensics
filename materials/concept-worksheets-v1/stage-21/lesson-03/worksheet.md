# Worksheet: Choose the Next Evidence Collection

## Status and required input

**Synthetic exercise—not a captured incident or observed result.** No Project 7 packet file was supplied. Lesson premise: Wireshark might show a workstation's encrypted connection within a defined incident time window. It is not a finding from an available case capture. The file, frames, host, peers, times, process, owner coverage, retention, and clock difference remain unknown.

Required input: this worksheet only. Setup/loading: none. No capture or DNS fixture is required. The verified `practice/dns-baseline/README.md` and its fixture are unrelated.

> A crucial record may vanish while you request six others.
>
> Which comes first?

Use `unknown—not supplied` for absent facts. Do not invent values.

## Request-record schema

| Field | Meaning |
|---|---|
| Packet basis | Source file, frame references/time, peers, observation point, and capture scope/window |
| Question | One missing fact that could change the response decision |
| Owner | Person or team able to confirm and preserve the source |
| Coverage | Whether logging covered the device and window |
| Loss risk | Retention, overwrite, shutdown, or another owner-confirmed availability risk |
| Timing | Original timestamps, time zone, and measured clock difference—or uncertainty |
| Limits | What the source cannot establish |
| Handling | Collector, source/export, preservation, and access restrictions |

## 1. Establish the packet boundary

Enter absent case values correctly, then list checks for a future authorized capture.

- Case file, frames, frame time, peers, host, and window: ______________________________
- First checks, including observation point and scope: ______________________________
- What packets cannot establish here: ______________________________________________

## 2. Draft the main request

Assume only that process ownership would change the response lead's understanding.

- Decision-changing question: ______________________________________________________
- Source owner/team: _______________________________________________________________
- Smallest request—device and connection identifiers, window, reason, and record type:  
  _________________________________________________________________________________
- Questions about auditing/coverage, retention/overwrite, time zone, clock difference, and preservation:  
  _________________________________________________________________________________
- Data minimization, documented export, provenance, and access controls:  
  _________________________________________________________________________________

## 3. Request-and-preservation grid

Preserve a parallel source only when its loss risk warrants it; otherwise record urgency as unknown.

| Role | Exact question | Source/owner | What it may answer | What it cannot answer | Coverage/timing | Loss risk | Action |
|---|---|---|---|---|---|---|---|
| Main request |  |  |  |  |  |  |  |
| Parallel candidate |  |  |  |  |  |  |  |

## 4. Synthetic changed-question exercises

For each changed question, select a source owner and state one limitation.

| Changed question | Source/owner | Limitation |
|---|---|---|
| Account or device use around the session |  |  |
| Name linked to the requesting host |  |  |
| Request forwarded by a proxy |  |  |
| Address translation blocks attribution |  |  |
| Activity beyond the capture window |  |  |

## 5. Handoff

- Packet basis and provenance: _____________________________________________________
- Hypothesis, request, and owner: __________________________________________________
- Preservation need and verified reason—or unknown: ________________________________
- What the source may answer and what remains unknown: _____________________________
- Timestamp, time-zone, and clock-difference status: _______________________________
- Collection handling and access restrictions: ____________________________________