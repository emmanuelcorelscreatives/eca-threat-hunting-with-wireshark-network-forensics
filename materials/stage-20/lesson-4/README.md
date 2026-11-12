# Project 7: From Suspicious Download to Outbound Transfer

This complete, separate Academy case is an offline synthetic worked practice. It supplies actual inspectable packet files and numbered context records for the lesson's conditional investigation. It is not the absent historical case described in the saved video. The narration remains unchanged. No network contact, harmful payload, credentials, or production data is needed.

Start with [setup.md](setup.md), complete [worksheet.md](worksheet.md), and then compare [answer-guide.md](answer-guide.md). Both packet files use classic `.pcap`, replacing the older proposed `.pcapng` filenames. All names below are included beside this guide.

| Files | Purpose |
|---|---|
| supplemental-edge.pcap; supplemental-internal.pcap | 54 edge frames and 9 internal frames, with valid bidirectional TCP exchanges |
| supplemental-manifest.json | Exact file hashes, format, clocks, coverage and declared collection gap |
| supplemental-identity-mappings.csv | Numbered time-bounded mappings I1–I3 |
| supplemental-host-events.csv | Numbered synthetic host excerpts H1–H4 |
| supplemental-business-context.csv | Numbered activity/role records B1–B4 |
| offline-builder.py; edge-spec.json; internal-spec.json | Standard-library offline reproducible packet writer and full input data |
| executed-commands.json; *-frames.stdout.txt; *-http.stdout.txt; *-conversations.stdout.txt; *-follow.stdout.txt; *-expert.stdout.txt | Actual TShark execution and outputs, with companion stderr files |
| rebuild-proof.json | Actual fresh byte-identical rebuild and existing-output refusal evidence |

These small packet files are deliberately readable. The recurring status service and ordinary backup are alternative explanations to test. The later upload has visible harmless sample text, but the records do not classify a real document or associate a PID with its connection. Same asset and close times support chronology; they do not establish causation, execution, attacker control, successful SSH authentication, or sensitive-data loss.

`check_capture.py` reads and verifies exact supplied hashes, classic-PCAP framing, every IPv4/TCP checksum and packet count independently of the builder. Run `python3 check_capture.py supplemental-edge.pcap edge` and `python3 check_capture.py supplemental-internal.pcap internal`. Reports and four corrupt-input rejection receipts are included as `independent-raw-report.json` and `independent-rejection-proof.json`. Exact hashes are checked first, so a hash rejection does not by itself prove the deeper parser ran on the corrupted file.

See `native-validation.md`, `native-host-platform.json`, `native-independent-approvals.json` and six `native-edge-*.png` images for bounded actual Linux GUI observations and their exact independent approvals.

`http-framing-raw-verification.json` parses actual packet bytes, separates HTTP headers at CRLFCRLF and checks declared lengths against actual body bytes. Upload frame49 has89 header bytes plus472 body bytes =561 TCP bytes; Content-Length472 is complete.
