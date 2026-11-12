# Offline setup and actual command checks

Use Wireshark/TShark 4.4.0 on the lecture's Ubuntu 24.04 workstation, or a compatible installed version for optional replay. The recorded reference CLI runs actually used native Linux TShark 4.4.0. A later GUI proof, if delivered, states its own actual platform. No live capture permission or root access is needed. Keep the original PCAP read-only and work on a copy if annotating.

1. Unpack the complete lesson ZIP or download `practice/ssh-auth-correlation/` from the public Academy repository.
2. Check the PCAP SHA-256: `7816d517c4d6db670421d1d1ba60d4926ba3bf2efb6e9f9878790936b395a79c`. Use `sha256sum ssh-auth-practice.pcap` on Linux or `Get-FileHash .\ssh-auth-practice.pcap -Algorithm SHA256` in PowerShell. PowerShell is an alternative command, not a claimed Windows execution here.
3. Choose File → Open in Wireshark, select `ssh-auth-practice.pcap`, and supply no read filter. This is a provided new exercise, not the empty original-case chooser in the saved lecture.
4. Choose View → Time Display Format → Date and Time of Day. That uses the viewing computer's local zone. Record that zone. For a UTC comparison you may explicitly select UTC Date and Time of Day instead; record the choice. Neither option measures or corrects capture-clock error. Keep journal receipt times as their own time basis.
5. Apply `tcp.stream == 0`. Inspect the opening SYN, SYN/ACK, ACK in frames 1–3 and SSH identification exchange in frames 4 and 6. Open Statistics → Conversations and select TCP. Record both endpoint directions, start and observed duration, not a signed-in user.
6. Inspect `sanitized-auth-records.csv` and `training-address-map.csv`. Preserve original message fields and raw loopback endpoints; use the explicitly documented offline alias transformation for comparison. Do not describe it as measured NAT.

Optional exact offline reconstruction with standard Python3: `python3 rebuild_capture.py --output reproduced.pcap`. This reconstructs captured records from `replay-records.json`; it does not generate a new handshake, authentication outcome or timestamp. Existing output is refused. Compare its SHA-256 with the value above. No third-party Python package or private key is required.

Read `actual-execution-proof.json` and the matching stdout/stderr files for actual reference commands and software. `packet-transformation-proof.json` records payload preservation and checksum verification. A checksum pass establishes internal consistency, not real-world identity. The PCAP has 27 frames and one TCP stream; the `ssh` display filter alone excludes TCP-only frames and is not the complete connection.
