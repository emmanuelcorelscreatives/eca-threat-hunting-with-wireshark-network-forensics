# Evaluate Fingerprints and Infrastructure Similarity — Worksheet

**Required downloads when released:** `worksheet.md` (this file: setup, inputs, schema and form) and `answer-guide.md` (key). Save both; answer questions 1–4 offline, then consult the key. No other inputs, shared prerequisites, capture, secrets or Wireshark are required. These drafts are not claimed as hosted downloads.

**Synthetic fictional exercise—not case evidence or Wireshark output.** All timestamps are UTC. `.test` names and IP addresses are documentation examples. `SYM-*` values are symbolic comparison tokens, not measured fingerprints. `—` means unavailable, not proof of absence.

**Schema:** `host / src → dst` = fictional endpoint/source/destination (`—` endpoint unknown); `side` = capture side; `DNS` = paired A-query time → response time / answer; `seen` = first seen, not proven connection start; `C/S` = supplied ClientHello/ServerHello availability; `tokens` = JA3/JA3S/JA4; `TLS` = version; `cert` = certificate visibility, not existence; `context` = fictional inventory/ownership note.

| Card | host / src → dst; side | DNS name; query → response / A answer | seen | C/S; tokens; TLS; cert | context |
|---|---|---|---|---|---|
| C1 | 192.0.2.10 / 192.0.2.10 → 203.0.113.20; endpoint-facing | alpha.example.test; 2030-01-02T10:00:00Z → 2030-01-02T10:00:01Z / 203.0.113.20 | 2030-01-02T10:02:00Z | yes/yes; SYM-J1 / SYM-S1 / SYM-4A; 1.3; no | process/ownership unknown |
| C2 | 192.0.2.10 / 192.0.2.10 → 203.0.113.21; endpoint-facing | beta.example.test; 2030-01-02T10:06:00Z → 2030-01-02T10:06:01Z / 203.0.113.21 | 2030-01-02T10:08:00Z | yes/yes; SYM-J1 / SYM-S1 / SYM-4A; 1.3; no | process/ownership unknown |
| L1 | 192.0.2.11 / 192.0.2.11 → 198.51.100.25; endpoint-facing | agent.example.test; 2030-01-02T10:10:00Z → 2030-01-02T10:10:01Z / 198.51.100.25 | 2030-01-02T10:13:00Z | yes/yes; SYM-J1 / SYM-S2 / SYM-4A; 1.3; no | approved agent listed on similar host; no packet-to-process mapping |
| P1 | — / 192.0.2.50 → 203.0.113.21; proxy-external | — | 2030-01-02T10:20:00Z | yes/no; SYM-J1 / — / SYM-4A; —; no | TLS-terminating intermediary; endpoint unknown |
| M1 | 192.0.2.10 / 192.0.2.10 → 203.0.113.22; endpoint-facing | — | 2030-01-02T10:25:00Z | no/no; — / — / —; —; no | earlier handshake possible, not established |

1. For C1/C2, relate each DNS answer to its destination and first-seen time. Why is this a lead, not proof the name caused the session?

   Answer: ____________________________________________________________________

2. Compare C1/C2 tokens. How does L1 test legitimate reuse? Are JA3 and JA4 independent confirmations?

   Answer: ____________________________________________________________________

3. Whose ClientHello might P1 show? What can M1’s missing handshake establish?

   Answer: ____________________________________________________________________

4. Are certificates comparable? Give an alternative explanation, bounded confidence and one authorized follow-up request.

   Answer: ____________________________________________________________________

## Real-capture observed evidence — leave blank

No case capture is supplied. Card IDs are **not** frame citations.

- Brief host/window: ______; original file/working copy: ______; capture point/coverage/side: ______; source identity/direction/proxy or NAT mapping: ______.
- DNS query/response/address/time and frames: ______; session source/destination/direction/time and frames: ______.
- ClientHello/ServerHello/certificate frames: ______; installed version, checked JA3/JA3S/JA4 fields, values or reason unavailable: ______; approved-agent comparison: ______.
- Observed evidence: ______; inference: ______; alternatives: ______; limitations: ______; confidence: ______; authorized follow-up: ______.

**Future authorized capture only:** Open a working copy; record scope and coverage before comparison. In the saved Windows 11 and Wireshark 4.4.0 example, use `dns`, then `tls`; for captured, decoded handshakes use `tls.handshake.type == 1` (ClientHello) and `tls.handshake.type == 2` (ServerHello). Under View > Internals > Supported Protocols, check this build and search fields for JA3, JA3S and JA4. Record installed version and checked field. Filters cannot restore an uncaptured handshake.