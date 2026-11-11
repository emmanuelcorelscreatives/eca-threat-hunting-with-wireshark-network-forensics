# Unified Evidence Timeline data dictionary

- **Sources:** `source_id` is stable; `source_class` is capture, endpoint log, identity log, resolver log, or other log. Record the producing system or observation point and distinguish original from working-copy references.
- Documented collection bounds differ from first and last records, which do not prove continuity. Record the window basis, gaps, direction or event scope, and available file or interface details.
- Clock precision is granularity; clock accuracy is trust and may be `unknown`. Record a measured correction only with its evidence.
- **Observations:** IDs, source ID, locator, and type trace the record. Preserve the complete original timestamp, provenance, zone basis, identifiers, and only what the record supports.
- Keep zone normalization, measured correction, correction evidence, comparable UTC, supported bounds, ordering uncertainty, coverage limits, and working-copy reference separate. Justified UTC text ends in `Z`; unresolved-zone UTC stays blank.
- **Proposed Links:** reference two separate observation rows. Record the link as a question; assess time, mapping validity, behavior, coverage or filtering, the strongest alternative, the distinguishing record needed, and status or missing field.


The supplied workbook has headers only: zero case data rows. A blank value is unknown or not supplied, never evidence of absence. All columns use text formatting to preserve source timestamps and identifiers; enter calculated or corrected UTC only when justified and keep the original wording.
