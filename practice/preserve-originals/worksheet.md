# Worksheet

1. State the handling hypothesis: does the named working file match the authorized received-file baseline **at the times checked**? Identify the handoff path, case path, and whether this is an authorized case or the optional synthetic lab.
2. Record the supplier person/system, recipient, arrival date and time **with time zone**, and received filename and full path. Mark unavailable facts `unknown`; do not infer a collector from a hash.
3. Before copying, record the full received SHA-256. Copy to `original/capture.pcapng`; record its full path and hash, then the observed received-versus-original result. Stop on a failure or mismatch.
4. Copy from the verified original to `working/capture.pcapng`. Record its full path, hash, and observed original-versus-working result. Independently recheck the paths and hashes.
5. If authorized and checks match, identify the full `working` path selected through Wireshark File > Open. If not opened, record `not opened`. Which file remains untouched? Why is Save As not the copy step?
6. Explain an alternative cause of a mismatch and the next useful check. Explain why equal hashes do not establish collection completeness, bidirectional visibility, or packet meaning. No packet filter, pivot, frame number, or finding is required here.
7. **Do not create a derivative.** Describe the distinct path, full hash, preserved-source link, change description, and handling details a future edited or sanitized copy would need.

Next lesson: assess what the preserved capture can show about truncation, drops, and missing directions; do not perform that assessment here.