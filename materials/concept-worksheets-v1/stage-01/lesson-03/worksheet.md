# Worksheet: Signal, Hunt, or Response?

Use only the synthetic input in `setup.md`. Preserve unknowns rather than inventing findings.

## Evidence-status key

- **Reported:** supplied as a monitoring statement but not independently established.
- **Hypothetical:** a possibility or proposed test.
- **Observed:** directly supported by supplied evidence; none is supplied here.
- **Unknown:** the supplied inputs cannot answer it.

## 1. Classify and triage the lead

Restate the lead: ________________________________________________

Evidence status: ____________________

What does the signal actually support, and what does it not prove?

__________________________________________________________________

### Triage questions

1. What missing detail is needed to identify the unfamiliar peer and permit a precise comparison?

   ______________________________________________________________

2. What authorized information would show whether the peer was expected for `SYN-WS-01` and whether the evidence matched the report?

   ______________________________________________________________

3. What context would test the scheduled-software explanation?

   ______________________________________________________________

## 2. Frame a bounded hunt

| Field | Your entry |
|---|---|
| Lead | ______________________________ |
| Evidence status | ______________________________ |
| Behavior to compare | ______________________________ |
| Asset(s) | ______________________________ |
| UTC window | ______________________________ |
| Authorized evidence and coverage needed | ______________________________ |
| Ordinary alternative | ______________________________ |
| Missing context | ______________________________ |
| Decision route | ______________________________ |

Write one testable hunt question about `SYN-WS-02`:

__________________________________________________________________

Why does the unspecified peer prevent a precise comparison now?

__________________________________________________________________

## 3. Test the coverage limit

Could a capture covering only `SYN-WS-01` settle whether `SYN-WS-02` made a similar contact? Why?

__________________________________________________________________

Status of the answer about `SYN-WS-02`: ____________________

Additional coverage or context needed: ____________________________

List two things packet bytes alone cannot establish:

1. __________________________  2. __________________________

## 4. Choose a route and draft a handoff

Mark each route as **current**, **conditional**, or **unsupported**:

- Explain or triage the reported signal: ____________________
- Propose a bounded hunt: ____________________
- Incident-response handoff: ____________________

If organizational incident criteria are met, what takes priority?

__________________________________________________________________

Handoff:

- Reported lead: ________________________________________________
- Proposed search: ______________________________________________
- Ordinary alternative: _________________________________________
- What remains unknown: _________________________________________
- Evidence needed next: _________________________________________