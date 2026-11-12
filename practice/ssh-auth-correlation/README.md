# Correlate remote access with identity events

Emmanuel Corels Academy · Threat Hunting with Wireshark: Network Forensics · Stage 18, Lesson 3.

This is new, controlled Academy practice for the lecture's **SSH authentication** branch. It is not the unavailable original case, a Windows event 4624 dataset, a production incident, or evidence of a real organization's assets. The authored lecture remains unchanged.

Start with [setup.md](setup.md), complete [worksheet.md](worksheet.md), then compare [answer-guide.md](answer-guide.md). All files are self-contained under `practice/ssh-auth-correlation/` in the course repository. Download this directory or the lesson's offline ZIP. No live login, private key, server, account or Internet service is needed to complete the exercise.

The PCAP contains 27 actual captured frames from a tightly restricted Academy loopback SSH session. Offline transformation replaces addresses and the server port with clearly documented classroom aliases and recalculates checksums. TCP payloads, timestamps, sequence numbers and order are unchanged. The sanitized server excerpt contains 11 actual records. The capture has an opening handshake but **does not include session closure**; do not confuse its roughly 0.294-second observed span with the full client lifetime or log coverage. Encrypted packets do not disclose the account or executed command.

Keep three columns: network observation, server-record observation, and inference. The accepted account is `root` in this one restricted lab, not a recommendation to enable root logins. The source controlled server is stopped and no keys are included. Logging and clock limits remain explicit. Training aliases are not observed NAT or historical DHCP records.
