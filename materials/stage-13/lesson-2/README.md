# Threat Hunting with Wireshark Course — Stage 13, Lesson 2: Measure Inter-Arrival Timing

Instructor: **EMMANUEL CORELS**. This supplemental Academy exercise does not change the lecture. The next lesson is **Interpret Jitter, Gaps and Long-Lived Sessions**.

**Measure comparable beginnings, not nearby packets.** A TCP connection attempt and an HTTP request start are different events; requests can reuse a connection. A SYN retry is not a new attempt. Even repeated, verified gaps do not establish a process, remote instructions or command and control. Scheduled software and other ordinary explanations remain possible.

## Choose your source

- **Packaged practice:** `practice.pcap` is separately labelled **synthetic Academy coursework**, not the unavailable historical incident. Its documentation-network addresses, frames and intervals are not real-case findings. Read `scope-card.md`, then follow `setup.md`. The packaged capture has SHA-256 `de49b4bc93e17959c8bfad00ad38b580e358d0e8f4adb8c5c90e375b413b72a0`. Verify the copy you actually open.
- **Your own authorized offline capture:** This is future learner work, not a completed learner investigation. Obtain an existing capture you are permitted to inspect, or collect one only through an approved process within its authorized scope. Do not generate or inspect unapproved network traffic. Preserve the original, calculate its SHA-256, and work on a copy. Obtain the actual client, peer and peer TCP port, capture window and point, time zone, collection directions, clock information, loss or drop information, and any address-translation mapping. Record what is unknown. Replace *all* fixture addresses and frame numbers with observations from that source. If requests are encrypted or not decoded, do not invent request starts; if only one long-lived connection is visible, do not invent a series of connection starts.

## Use the supplied materials

1. `setup.md` gives the native Wireshark workflow, exact fixture filters, timing menus, a safe optional rebuild and recording instructions. `scope-card.md` identifies the synthetic scope and its limitations.
2. Use the header-only `worksheet.csv`, guided by `worksheet.md` and `DATA_DICTIONARY.md`, for candidate decisions, original frame numbers, timestamps, streams, separate event series and subtraction. **The CSV has no columns for the original capture hash or scoped peer port.** Include the following labelled fields in the narrative portion of your submitted worksheet response alongside the CSV; do not put `IP:port` in the CSV's IP-only `scope_peer` column or silently change the supplied header:

   - **Original capture file and SHA-256:** __________
   - **Opened working copy and SHA-256:** __________
   - **Scoped client IP:** __________
   - **Scoped peer IP:** __________
   - **Scoped peer TCP port:** __________
   - **Capture window, time zone and capture point:** __________
   - **Authorization, collection directions, clock, loss and translation notes or unknowns:** __________

   Confirm these values for the source you actually used. The scope card's client-facing capture point is authored scenario information, not proof of real collection coverage.
3. Complete and check your decisions before consulting `answer-guide.md`, which is a **fixture-only** answer key. `checker-usage.md` explains the actual independent byte-level report and what its pass does *not* prove. `all-frames.stdout.txt`, `decoded-fields.stdout.csv`, `capture-info.stdout.txt` and the conversation and protocol-hierarchy logs provide separate recorded decoder evidence. `native-independent-approvals.json` identifies the exact approved, role-limited native PNG views. None is an approval of an unseen setting or a real case.

`executed-fixture-spec.json` is the actual recorded fixture input; `fixture-plan.json` is an earlier design alias. `offline-builder.py` and `check_capture.py` are the packaged builder and independent checker. `builder-safety-and-rebuild-execution.json` records a fresh matching rebuild with the current exclusive-creation builder and two overwrite refusals. `independent-pcap-execution.json` and `independent-pcap-report.json` record the separate checker execution. **`historical-actual-execution-proof.json` is an immutable earlier execution record, not an inventory or status report for the current files.** Its former builder hash, CSV-header entry and pending-prose status must not be used as current facts. The recorded checker argv names an earlier path for byte-identical checker code; the packaged name is `check_capture.py`. The examples in these guides are proposed learner commands, not claims that those exact command lines were executed.

The current worksheet, setup and answer guide distinguish actual checker and GUI observations from future learner work. The four independently approved `native-gap-*` views now demonstrate an out-of-filter response-frame reference and its effect on the displayed-row shortcut. Current inventory bindings are separate from the historical manifest. Complete independent review, repository publication, main visual approval and rendering are still separate requirements; no verified public download is claimed at this assembly stage.
