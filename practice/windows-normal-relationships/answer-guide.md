# Checked answer guide

All values below were derived from actual dissection of this kit's synthetic bytes. See command-0..4 stdout and execution.json for executed commands. They describe an authored fixture, not a live server transaction.

18 frames span 2025-01-16 12:01:00.000000 through 12:07:00.050000 UTC (360.05 s). Three TCP streams each contain six frames and last 0.05 s. Display filter `smb2 && ip.addr == 192.0.2.21` returns exactly 4, 5, 10, 11, 16, 17; `smb2` returns the same six. No malformed frames were decoded by the recorded TShark check.

| Stream | Client → server | Request → response | Request UTC | Share | Message ID / Tree ID | Context |
|---|---|---|---|---|---|---|
| 0 | 192.0.2.21:50001 → 192.0.2.40:445 | 4 → 5 | 12:01:00.030000 | TeamDocs | 1 / 1 | WS-ALPHA → FS-TEAM role-aligned; ACT-01 covers time/share |
| 1 | 192.0.2.70:50002 → 192.0.2.21:445 | 10 → 11 | 12:04:00.030000 | ADMIN$ | 1 / 2 | MGMT-OPS → WS-ALPHA administration aligned with ACT-02 |
| 2 | 192.0.2.21:50003 → 192.0.2.22:445 | 16 → 17 | 12:07:00.030000 | ProjectDrop | 1 / 3 | WS-BRAVO inventory incomplete; no matching activity row; unexplained |

Each response arrives 0.01 s after its request, has response flag True, command 3, Message ID 1 and NT status 0x00000000 (STATUS_SUCCESS). Match Message ID within its TCP stream, not globally. Paths in requests are `\\192.0.2.40\TeamDocs`, `\\192.0.2.21\ADMIN$`, and `\\192.0.2.22\ProjectDrop`. Tree IDs appear in responses. There are no SMB authentication/session setup exchanges, so these packets cannot demonstrate actual authenticated identities or reconstruct full SMB sessions.

IPv4 Conversations reports 192.0.2.21 ↔ 192.0.2.40 = 6 frames, 526 bytes; 192.0.2.70 ↔ 192.0.2.21 = 6 frames, 522 bytes; 192.0.2.21 ↔ 192.0.2.22 = 6 frames, 532 bytes. In each listed client→server direction there are four frames; reverse has two. Forward/reverse bytes are 334/192, 330/192, 340/192 respectively. Relative starts are 0, 180 and 360 seconds. These counters include packet headers and do not establish transferred file data. Sum packet bytes is 1580; filesystem PCAPNG length is 2236 bytes, a distinct quantity.

The bounded classification is explained-by-supplied-context versus unexplained, not benign versus malicious. An incomplete inventory, temporary collaboration or support activity could explain ProjectDrop. Ask the responsible owner for contemporaneous approval, share audit, identity, process and file activity records. Absence of an activity row does not prove unauthorized behavior. No packets establish human identity, purpose, Windows OS version or compromise; all asset roles and approval data are synthetic context. The optional learner follow-up has no author-provided results.

If relevant SMB content is encrypted, packet inspection may reveal peers, timing and other visible metadata while hiding share names and operations. Do not infer hidden shares or file actions; seek authorized host/service audit and identity records, and document the visibility limit. This cleartext synthetic exercise does not demonstrate decryption.
