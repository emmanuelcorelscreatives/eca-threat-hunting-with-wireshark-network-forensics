# Explain what HTTPS hides: local comparison lab

This is a separate Academy exercise supporting Stage 10 Lesson 6. The saved lesson's original case supplied no capture; these new files do not resolve it. Both PCAPs are actual Linux loopback collections of owned, scripted TLS 1.3 sessions. The traffic source is synthetic; packets were collected, not assembled from invented bytes. The candidate label is a role for a lead, not maliciousness. The updater is ordinary by scripted provenance, not packet inference.

Start with `setup.md`, complete `worksheet.md`, then compare `answers.md` and `verified-results.json`. `captures/fixture.json` supplies mapping, simulated report anchors and limitations; `captures/endpoint.jsonl` is authored mock evidence, not collected endpoint telemetry. `data-dictionary.md` explains the fields. `commands-and-evidence.json` retains executed CLI checks. No certificate, private key, TLS session key or decrypted object is delivered.

There is no earlier lesson prerequisite file. Python 3 and TShark validate the supplied captures without network access. Wireshark supports the interactive exercise. Building a fresh collection is optional and needs Linux, tcpdump capture privilege and OpenSSL. The normal student workflow opens the supplied PCAPs. File-specific answers apply only to these exact bytes. Fresh TLS randomness, ports and timing make rebuilds different: run the checker again for new answers.

This kit does not approve main-video visuals or claim a native GUI walkthrough was executed. GUI tasks are student instructions; actual retained execution evidence is TShark and the collection application receipts. Source, instructor, lesson IDs and schedules remain unchanged.
