# Worksheet — TEMPLATE: PLAN FOR A FINDING, NOT A FINDING

No case file is loaded. Use blanks or `<PLACEHOLDERS>` for this rehearsal, or later enter only authorized evidence.

## 1. Scope, time, and identity
- Source file: __________  Capture point: __________
- Displayed time zone: __________  Start/end: __________ / __________
- Known gaps, excluded directions, or visibility boundary: __________
- Original host timestamps and clock notes; do not normalize until offsets are checked: __________

| Role | Asset identifier | Packet address | Valid from/to in original clock | Identity record/reference | Mapping status |
|---|---|---|---|---|---|
| | | | | | |

**Q1. Where does capture visibility stop, and why cannot an absent conversation prove no action occurred?**  
Answer: ________________________________________________________________

**Q2. What record establishes who held each address during the bounded window?**  
Answer: ________________________________________________________________

## 2. Packet observations
In an authorized capture, `smb2` finds decoded SMB traffic only. Keep observation separate from interpretation. A reviewer must locate the packet rather than rely on a screenshot.

| ID | Source file/frame | Timestamp/time zone | Direction | Decoded operation | Request/response and relevant response | Packet-supported claim | Interpretation | Coverage/exchange limit |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | |

Encrypted payload or incomplete-exchange limit: __________________________  
What do responses and surrounding traffic establish? _____________________

## 3. Claim ledger
| Claim level | Evidence references | Status | Confidence for this claim | Unavailable evidence |
|---|---|---|---|---|
| Connection or share access | | | | |
| File transfer | | | | |
| Target-host execution | | | | |

Use `observed`, `inferred`, `unresolved`, `not provided by lesson`, `not collected`, `expired`, or `unknown`. A tree connection or share access does not prove copying or execution. A file-open request is not a transfer; a write does not prove execution. Administrative-share use requires role and authorization context.

**Q3. What is the strongest claim the cited packets support, and what remains unresolved?**  
Answer: ________________________________________________________________

## 4. Competing explanations and cross-checks
| Possibility to test—not a case fact | Operational record and owner needed | Do source, targets, role, operations, and time match? |
|---|---|---|
| Approved deployment | | |
| Administrator work | | |
| Backup activity | | |

Possible cross-checks, only if enabled and retained: Windows event 5145 records a file-share access check; requested rights do not prove copying or execution. Event 4688 may show a new process, but its command line may be absent. Match the target, checked timing, address holder, account or job, and linkage basis. Missing or expired records cannot refute the hypothesis.

**Q4. Name one target-host record for suspected follow-on action and one approved-job record that could explain the pattern.**  
Answer: ________________________________________________________________

## 5. Focused evidence request
- Record owner: __________  Source/targets: __________
- Bounded window and time basis: __________
- Record type and one question: _________________________________________
- Authorization context requested: __________
- Retention priority/status or unavailable note: _________________________

## 6. Conditional hypothesis and handoff
Between `<START>` and `<END>`, the identified source `<SOURCE_ASSET>` contacted named targets `<TARGETS>`. It performed only `<OPERATIONS SUPPORTED BY CITED SOURCE FILE AND FRAMES>`. These observations raise a question about movement between systems, pending target-host confirmation.

Observed: __________  Why investigate: __________  
Strongest ordinary explanation: __________  Missing evidence: __________

### Self-check
- [ ] Source, targets, time basis, and capture boundary are identifiable.
- [ ] Every packet claim has source-file and frame references.
- [ ] Share access, transfer, and execution remain separate claims.
- [ ] Original timestamps and uncertainties are preserved.
- [ ] The statement is conditional and does not claim confirmed compromise.