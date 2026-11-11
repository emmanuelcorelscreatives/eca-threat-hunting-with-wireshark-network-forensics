# Setup and schema

## Required setup
Use `setup.md`, `worksheet.md`, and `answer-guide.md` with a UTF-8-capable Markdown editor. No capture is required. Case captures and records were not supplied; add no factual source, event, time, frame, address, asset, or observation-point rows.

If authorized working copies arrive, keep originals unchanged and separate. Give each source an identifier tracing its original and a different working-copy label. Retain supplied collection notes; do not infer a sensor location.

## Status vocabulary
Leave unsupported values blank and place a status beside them:
- `unknown`: the value is not known or supplied.
- `unavailable`: the needed detail or supporting record is not available.
- `unverified`: continuity or a clock relationship has not been checked.
- `unresolved`: an analytical determination cannot be made.

Clock-correction classes are `documented`, `estimated`, or `unavailable`. An estimate still requires stated support and uncertainty; it is not a guess.

## Data dictionary
- **Source coverage:** original-tracing identifier, working-copy label, observation point, collection notes, first/last displayed times, displayed zone, file/interface details, continuity, and gaps.
- **Clock:** original displayed time and its displayed zone, named chosen common-time reference and zone, common time only when the relationship is supported, correction class, reason, amount, and uncertainty. Retain both times.
- **Address mapping:** observed time/source, numeric address, assignment validity interval and record, asset, hostname lead, translation record/time, and mapping status.
- **Window placement:** lower/upper bounds, packet or record support, per-source coverage/gaps, edge check, possible activity, alternative, and ordering/status.
- **Gap request:** proposed missing record, exact question it could resolve, recipient (blank if unknown), recipient status, and request status (`draft/not sent` unless submission is documented).

## Workflow when files become available
1. Open each working copy separately. In `Statistics → Capture File Properties`, record first/last packet timestamps and available file/interface details.
2. Select absolute date-and-time under `View → Time Display Format`; record the viewing computer’s time zone. `Seconds since the first packet` restarts per file. A display-zone change does not repair drift.
3. First/last times are capture metadata, not continuity or incident bounds. Without supporting notes, mark continuity `unverified` and draw no solid coverage bar.
4. Correct only from a matched independent event or trustworthy clock record. Close times alone are insufficient. Before `Edit → Time Shift`, document reason, amount, and uncertainty; use a working copy and save separately. The shift also affects packets hidden by a display filter.
5. Validate numeric addresses with time-covering assignment records and require time-matched translation evidence where applicable. Treat hostnames only as leads. After support exists, set provisional bounds and separate source lanes. Include both conversation directions and check window edges; display filters change only the view.