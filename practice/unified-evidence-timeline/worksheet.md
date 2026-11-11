# Unified Evidence Timeline — Blank Worksheet

**Evidence status:** No case files or observations were supplied. This is not a reconstructed case. Use only authorized material; do not fill blanks with invented findings.

## Schema and acceptance targets

These are specifications, not executed results: three sheets; 16, 18, and 11 columns respectively; zero data rows.

### Sources

```text
source_id,source_class,producing_system_or_observation_point,original_file_reference,working_copy_reference,documented_collection_start_original,documented_collection_end_original,first_record_original,last_record_original,window_time_basis_and_evidence,coverage_gaps,direction_or_event_scope,file_and_interface_details,clock_precision,clock_accuracy_or_unknown,measured_clock_correction_and_evidence
```

### Observations

```text
observation_id,source_id,record_locator,record_type,original_timestamp_text,timestamp_provenance_and_zone_basis,identifiers_as_recorded,observation_only,normalization_method_and_evidence,calculated_utc_from_zone,measured_clock_correction_applied,correction_evidence_reference,comparable_utc_if_justified,earliest_possible_utc_if_supported,latest_possible_utc_if_supported,ordering_uncertainty,coverage_limit_note,working_copy_reference
```

### Proposed Links

```text
link_id,observation_id_a,observation_id_b,proposed_link_question,time_window_compatibility_and_order_limits,identifier_mapping_evidence_and_validity,behavior_match_and_limits,coverage_and_filter_check,strongest_plausible_alternative,distinguishing_record_needed,status_and_missing_field
```

## Compact data dictionary

- **Sources:** `source_id` is stable; `source_class` is capture, endpoint log, identity log, resolver log, or other log. Record the producing system or observation point and distinguish original from working-copy references.
- Documented collection bounds differ from first and last records, which do not prove continuity. Record the window basis, gaps, direction or event scope, and available file or interface details.
- Clock precision is granularity; clock accuracy is trust and may be `unknown`. Record a measured correction only with its evidence.
- **Observations:** IDs, source ID, locator, and type trace the record. Preserve the complete original timestamp, provenance, zone basis, identifiers, and only what the record supports.
- Keep zone normalization, measured correction, correction evidence, comparable UTC, supported bounds, ordering uncertainty, coverage limits, and working-copy reference separate. Justified UTC text ends in `Z`; unresolved-zone UTC stays blank.
- **Proposed Links:** reference two separate observation rows. Record the link as a question; assess time, mapping validity, behavior, coverage or filtering, the strongest alternative, the distinguishing record needed, and status or missing field.

## Practical checks

1. Record validation counts: sheets ______; columns ______ / ______ / ______; data rows ______ / ______ / ______.
2. In the empty Wireshark workspace, what packet observation can be entered? ____________________. If authorized material exists: source class ______; original reference ______; observation point/window ______; working copy ______.
3. This is arithmetic, not a log entry or finding: nine o’clock at an offset of plus two hours, is seven o’clock UTC on the appropriate date. Show the calculation: ____________________.
4. For an unzoned local reading, calculated UTC: ______. Evidence needed: ____________________. Clock accuracy: ______.
5. Without inventing observations, list proposed-link checks: time ______; identifier mapping and validity ______; behavior ______; coverage/filter ______; alternative ______; distinguishing record ______; missing-field status ______.
6. When is sorted order unresolved? ____________________. Reverse-check locator, original time, identifiers, conversion, correction evidence, and copy reference. Failed fields: ____________________.

**Rule:** Nearby rows alone don’t prove a finding.