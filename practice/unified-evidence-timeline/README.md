# Unified Evidence Timeline

Emmanuel Corels Academy · Threat Hunting with Wireshark: Network Forensics · Stage 22, Lesson 1.

Open `unified-evidence-timeline.ods` in LibreOffice Calc 24.2. It contains three blank sheets: Sources (16 columns), Observations (18), and Proposed Links (11). These are the exact headers specified in the matching worksheet; there are no case observations. All authored columns preserve text rather than automatically interpreting timestamps or identifiers. Save an analysis copy before entering independently authorized evidence.

Read `setup.md`, complete `worksheet.md`, and check your reasoning against `answer-guide.md` and `DATA_DICTIONARY.md`. The blank workbook is a reusable source register, not an incident reconstruction or a replacement for missing captures/logs. Nearby rows do not prove a finding.

## Verification

Run `python3 verify_workbook.py` beside these files. The verifier checks exact headers, text column formats, empty data rows and full ZIP integrity, then opens and saves a separate temporary copy using an installed LibreOffice Calc. It preserves the supplied workbook. `validation.json` records the actual Academy validation with LibreOffice 24.2.7.2 on Ubuntu 24.04; it does not claim packet observations or Windows execution.
