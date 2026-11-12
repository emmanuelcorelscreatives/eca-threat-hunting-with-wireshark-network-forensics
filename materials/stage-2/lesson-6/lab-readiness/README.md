# Stage 2 Lesson 6 — Troubleshoot the Lab Before You Hunt

Start with [setup.md](setup.md), fill in [worksheet.md](worksheet.md), then compare [answer-guide.md](answer-guide.md). The [data dictionary](DATA_DICTIONARY.md) explains fields and the [native validation record](native-validation.md) links actual worked GUI evidence.

The worked reference is `lab-reference.pcapng`: an unchanged shared Academy synthetic DNS baseline converted to PCAPNG and mechanically checked. Its measured reference manifest, public-source provenance, source archive, preparation tool and exact command outputs are included. `practice.pcap` is a different synthetic six-frame exercise, with a deterministic offline builder and spec. Keep each file's own checks and dates.

The optional live assignment is separate and requires your own approved isolated lab plan. Offline success does not prove live traffic visibility. This kit contains no historical incident, learner-completed capture, host/process identity or maliciousness finding. Preserve uncertainty when checks disagree.

`current-kit-inventory.json` lists current delivered member SHA-256 values; the older `assembly-manifest.json` is a historical receipt of the prior draft. Earlier absolute paths in preserved stdout are execution provenance, not paths the student must have. Run current commands from this extracted directory.

The delivered `current-kit-inventory.json` is an inventory envelope: its `files` array covers every other delivered kit member and excludes the envelope itself to avoid a self-referential hash. The independent review binds the envelope separately by SHA-256, and publication/ZIP audits cover it as a delivered file.
