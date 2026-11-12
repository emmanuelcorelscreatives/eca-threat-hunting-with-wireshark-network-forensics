# Preserve Originals and Work on Copies

Stage 3 Lesson 2 supplemental Academy exercise. The saved lecture, instructor and original no-case-capture limitation remain unchanged. This is an isolated handling exercise, not a narrated incident or network collection.

Start with setup.md, then worksheet.md. Use Preserve-Copies.ps1 with notes-template.md and the supplied synthetic-handling-only.pcapng. synthetic-handoff.json describes its explicit synthetic identity, measured size and digest. synthetic-handling-only.pcapng.hex provides its exact hex representation; the downloadable binary removes any required conversion step. DATA_DICTIONARY.md explains the records. Consult answer-guide.md after completing your own checks.

The decoder files record actual Linux TShark 4.4.0 validation of this binary: valid empty pcapng, zero packets. Windows execution receipts, if supplied, describe only their stated actual scope. Neither implies a Wireshark GUI open or a historical case. Matching hashes prove content equality only at the checks. No packet analysis, sanitization or derivative creation is performed.

Actual portable-script validation is in powershell7-execution.json: Linux PowerShell7.6.9, received/original/working full digests MATCH, existing case/missing source/wrong extension and null digest rejected. This is not Windows5.1 execution. The original Windows narrated case exercise remains conditional on an authorized capture and handoff.
