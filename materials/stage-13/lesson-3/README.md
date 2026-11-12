# Interpret Jitter, Gaps and Long-Lived Sessions

Supplemental Emmanuel Corels Academy practice for Stage 13, Lesson 3, taught by **EMMANUEL CORELS**. The lecture and its original topics are unchanged. The original incident capture is unavailable; `practice.pcap` is a separate, explicitly synthetic exercise. It is not a historical incident or a learner-owned capture.

Use the fixture to compare regular, variable and apparently interrupted **TCP connection-attempt** spacing, remove a repeated SYN from the event count, and distinguish a long-lived TCP connection from visible HTTP requests and transport-only probes. Timing alone does not establish an application's purpose or command-and-control.

## Read and use the kit

1. Read `setup.md`. Preserve the original PCAP and analyze a hash-checked working copy. The fixture SHA-256 is `741a40d9c1d1d3e3361b2bc4a670b9a5cd7d2e3b1e9d60d215d356b6e9417eb4`.
2. Complete `worksheet.md`, including the actual capture filename and SHA-256, host and **peer port**, event definition, original frames and timestamps, coverage limitations, competing explanations, confidence and smallest useful next record.
3. Compare with `answer-guide.md` after making your own calculations. Three accepted starts supply only two successive intervals. A repeated SYN and the persistent connection's transport probes are not new application check-ins.
4. Use `DATA_DICTIONARY.md` for field meanings and `checker-usage.md` for the independent raw-packet checker. Consult `native-validation.md` and `native-independent-approvals.json` for the exact scope of actual author-provided GUI observations.

## Files and provenance

`practice.pcap` contains 33 packets in a 2,378-byte classic PCAP. The actual reproducible input is `executed-fixture-spec.json`; `offline-builder.py` creates a fresh output exclusively and refuses an existing pathname. `builder-safety-and-rebuild-execution.json` retains a matching fresh rebuild and overwrite-refusal checks. The older `timing-supplement.json` is planning provenance, not the executed spec.

`check_capture.py`, `independent-pcap-report.json`, `independent-pcap-execution.json` and `independent-checker-rejection-proof.json` record a separate raw-byte validation and bounded corrupt-copy rejection tests. `decoded-fields.stdout.csv` adds decoded flags and checksum fields to the older `all-frames.stdout.txt`. Other retained read-only logs cover Capture File Properties, TCP/IP Conversations, protocol hierarchy and a malformed-frame query. Their recorded argv and source paths are historical evidence, not a claim that a learner's PATH or machine has been tested.

`collection-ledger.csv` describes an authored synthetic vantage; coverage, drops and host schedule remain unknown. `native-file-accounting.json` distinguishes physical size, captured frame bytes and the recorded native Properties counter. The `native-*.png` files and their hash-bound approval ledger document only their actual visible roles. `one-second-frame-bin-arithmetic.json` is raw-record arithmetic, separately identified from GUI measurements. `current-kit-inventory.json` lists the other staged kit members; its own nonrecursive envelope is packaged separately. The immutable historical execution manifest is not a current Markdown inventory.

Earlier proposed names `build_fixture.py` and `timing-supplement.pcap` are not delivered aliases. Use the actual names above; the builder has no `--check` option. Repository publication and complete-course rendering require separate verification and are not established by these local evidence files.

## Separate authorized-file assignment

Make **three separate timing assessments in your own authorized capture**, without assigning a malicious label first. Preserve that file's source and capture point, window and precision, accepted events, exact filters, original frames, interval arithmetic, collection and scheduling alternatives, confidence limit and smallest useful next record. The synthetic attempts are not three proved application check-in sequences and do not replace that assignment. If an authorized file, collector-health record or host schedule is unavailable, record the corresponding finding as unresolved; do not borrow the fixture's conclusions.
