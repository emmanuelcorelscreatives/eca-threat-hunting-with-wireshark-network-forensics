# Setup and Synthetic Fixture

**Status:** Draft supporting artifact; separate review is required.

## Required downloads

- `setup.md` — instructions, fixture, and field dictionary.
- `worksheet.md` — blank comparison activity.
- `answer-guide.md` — fixed reasoning key.

Open the files in that order with a UTF-8 Markdown viewer or editor. No capstone capture or instructor answer pack was supplied. No packet file, private data, credential, or software execution is required. A prior learner response is optional and may be used only if it was written for this same S1–S3 synthetic fixture. If available, preserve it unchanged as the original; otherwise use Candidate A. Candidate B is a practice comparator, not an instructor solution. Do not use `practice/dns-baseline` as capstone evidence.

## Synthetic exercise fixture

**Synthetic only: this is not a captured incident or an observed result.**

- **S1:** In this hypothetical, a supplied network record establishes an encrypted conversation involving **System R** during an unnamed review window. Protected content is unavailable.
- **S2:** No endpoint, identity, proxy, ownership, or authorization record is included.
- **S3:** The record represents one observation point; path completeness is unknown.
- **Candidate A:** “The encrypted conversation proves System R exfiltrated files. Isolate it immediately.”
- **Candidate B:** “The encrypted conversation warrants review, but specific content, initiating process or user, authorization, and data loss are unestablished. Preserve the supplied record and ask System R’s owner for host activity and authorization records for the same window before deciding containment.”

## Field dictionary

- **Observation:** Only what S1–S3 state.
- **Inference:** An explanation extending beyond those statements.
- **Coverage limit:** What the observation point or missing records cannot establish.
- **Alternative:** Another explanation consistent with available evidence.
- **Next check:** A named owner and record that could reduce a named uncertainty.

Use only S1–S3. Enter **not supplied** for files, frames, addresses, timestamps, filters, or packet details. Do not fabricate them. No command or result is claimed.