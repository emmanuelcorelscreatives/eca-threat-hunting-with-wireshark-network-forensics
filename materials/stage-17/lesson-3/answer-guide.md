# Checked packet answers

The reference is admin-share-training.pcapng, SHA256 `f18eac0825c43b314bfe0257ccc58798860465dd1fb52a5319febd50ecf8235a`. Actual TShark decoding is retained in decoded-fields.stdout.txt and smb2-detailed.stdout.txt. The PCAPNG is authored, not a live capture. Its native interface says authored-offline-link.30 frames span 2025-02-10 09:05:00–10:00:00.702 UTC;18 are SMB2. Both TCP sessions include SYN/SYN-ACK/ACK and FIN/FIN-ACK/ACK boundaries. No modeled loss/retransmission, invalid IP/TCP checksum or malformed packet was found by the actual recorded check. This is limited to the authored model.

Comparison: 192.0.2.11:50101→198.51.100.20:445, original 1–12; six SMB2 frames 4–9. CH-09 names this admin source, destination, ADMIN$ and 09:00–09:15 window; its artifact is blank. Candidate: 192.0.2.10:50102→198.51.100.20:445, original 13–30;12 SMB2 frames 16–27. At 10:00 its role/time lacks matching supplied approval context. That warrants the specific approval lookup; the limited synthetic register cannot prove lack of authorization.

| Operation | Comparison request/reply | Candidate request/reply | Message ID | Result |
|---|---|---|---|---|
| NEGOTIATE |4/5|16/17|0|SMB 2.0.2 model|
| SESSION_SETUP |6/7|18/19|1|STATUS_SUCCESS; synthetic empty security tokens, no actor evidence|
| TREE_CONNECT |8/9|20/21|2|\\198.51.100.20\ADMIN$; STATUS_SUCCESS; tree70 or90|
| CREATE |none|22/23|3|eca-training-marker.txt; STATUS_SUCCESS; action Opened (1)|
| WRITE |none|24/25|4|offset 0; request 4 bytes 45434121(ECA!); response STATUS_SUCCESS,count 4|
| CLOSE |none|26/27|5|STATUS_SUCCESS|

Candidate session 900, tree 90. CREATE response 23 supplies file ID 11111111111111112222222222222222, retained by WRITE 24 and CLOSE 26 (Wireshark GUID display may insert hyphens). CREATE action Opened explicitly does not prove a new file. WRITE 25 reports 4 bytes for the matching request. Range[0,4) accounts for the supplied inert four-byte marker in this model; there is one write, no retries or second open file. The capture continues to clean TCP close, but no destination file/process/service record establishes durability, full real-world artifact provenance or execution. The minimal successful wire exchange deliberately omits realistic security authentication; do not use it as a model of valid credentials.

ADMIN$ is an administrative-share lead; C$ maps a local drive and IPC$ supports interprocess communication. None establishes actor identity, intent or approval. smb2.tree is present on decoded tree references and may also be state-associated with later frames; always return to the candidate pair to preserve complete operation coverage. Conversation total byte counts include transport/protocol overhead and are never the four-byte artifact's size.18 candidate full frames versus 12 SMB2 frames illustrates filter-scope differences.

Missing reply: classify as attempted write and request missing coverage, not failure. Mid-session start: missing earlier context prevents a no-access claim. Encryption: connection metadata cannot identify the hidden name/operations; request authorized destination evidence. Signing protects integrity and is not encryption. No encrypted traffic is provided in this fixture; these are reasoning questions.

Five-layer example: Observed—the explicitly authored candidate stream 1 contains accepted ADMIN$ tree 20/21, file open 22/23, four-byte write 24/25 and close 26/27. Inferred—the linked accepted operation supports the reported write within modeled coverage. Alternative—approved deployment or administration remains plausible; CH-09 covers another peer/time only. Unknown—real actor, authorization, durable destination file and any execution; no host/identity records are supplied. Next request—matching approval source/destination/share/artifact/time and destination file/process/service records around 10:00 UTC, correlated carefully to the network event. No malicious-execution finding follows from these packets.
