# Setup: Synthetic Paper-Only Fixture

**Status:** **SYNTHETIC PAPER-ONLY EXERCISE**—not a captured incident, packet finding, or software output. No Project 7 capture is supplied or implied. Do not use the unrelated DNS practice fixture.

## Required downloads

Use `setup.md` (fixture and dictionary), `worksheet.md`, and, after attempting the exercise, `answer-guide.md`. No shared prerequisite or capture is required. `null` means not supplied—not zero, absent, or disproved. Do not invent values or claim a citation was checked.

```json
{
  "label": "SYNTHETIC PAPER-ONLY EXERCISE",
  "case_context": {
    "investigation_question": null,
    "authorized_capture_window": null,
    "observation_point": null,
    "report_version": null
  },
  "original_capture": {
    "availability": "unavailable",
    "path": null,
    "recorded_hash": null,
    "coverage": null,
    "capture_point": null,
    "known_gaps": null
  },
  "working_copy": {
    "status": "mentioned but unvalidated",
    "path": null,
    "changes": null
  },
  "draft_claim": "‘The outbound session proves data was stolen.’",
  "citation": {
    "original_source": null,
    "frame": null,
    "timestamp": null,
    "time_basis": null,
    "direction_detail": null
  },
  "clock": {
    "relationship": "unestablished",
    "measured_offset": null
  },
  "evidence": {
    "content": "missing",
    "sensitivity": "missing",
    "authorization": "missing"
  },
  "record_owner_role": null,
  "decision_owner_role": null
}
```

## Dictionary

- `case_context`: question, scope, observation point, and report identity.
- `original_capture`: source identity, integrity record, coverage, and gaps.
- `working_copy`: lineage that cannot substitute for the original.
- `citation`: fields needed to relocate an observation and check direction.
- `clock`: whether source times are comparable; guessed offsets are not measurements.
- `evidence` and owner roles: support needed for a loss claim and actionable request.

Only if the Academy later supplies the authorized original: on Windows 11 with Wireshark 4.6.0, use **File > Open**, inspect **Statistics > Capture File Properties**, confirm **View > Time Display Format**, and use **Go > Go to Packet** for supplied frames. Until then, mark verification unresolved.