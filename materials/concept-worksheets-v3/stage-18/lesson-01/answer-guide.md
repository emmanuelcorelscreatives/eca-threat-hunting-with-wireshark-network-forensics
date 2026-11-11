# Answer Guide

Equivalent evidence-bounded wording is acceptable. No card proves misuse, completed login, identity, actions, or authorization.

| ID | Model reasoning, routine explanation, and record |
|---|---|
| RS-01 | **Port lead; low-confidence RDP candidate.** Port 3389 without setup cannot establish RDP or access. Routine administration is plausible; test asset inventory or a maintenance record. |
| RS-02 | **Decoded protocol; moderate-confidence RDP attempt.** One X.224 request supports initiation, not a reply or login. Missing direction could hide a reply. A routine administrator-initiated RDP attempt is a plausible alternative; test a source host process record. |
| RS-03 | **Recognizable setup exchange; high-confidence RDP setup.** Request, Confirm, and same-peer UDP strengthen service identification, not completion. Routine maintenance is plausible; test an approved maintenance-window record. |
| RS-04 | **Port lead; low-confidence SSH candidate.** Port 22 and a late window are not proof. A management-system connection is plausible; test asset or management-schedule records. |
| RS-05 | **Recognizable setup exchange; high-confidence SSH exchange.** Both identifiers outweigh the nonstandard port, but authentication and commands remain unknown. Approved routine SSH administration on a nonstandard port is a plausible alternative; test identity or source host records. |
| RS-06 | **Decoded protocol; moderate-confidence SSH.** SSH decoding and the stated later protected traffic show progression to protected traffic, but the late start leaves setup unseen and does not establish authentication or completed remote access. Routine administration is plausible; test host or identity records. |
| RS-07 | **Port lead with an HTTP-path clue; provisional, moderate-confidence WinRM candidate.** The HTTP request/reply and default `wsman` URL prefix strengthen the lead beyond a port alone, but HTTP decoding is not decoded WinRM, and SOAP management content is unavailable. Neither a WinRM operation nor a completed task is proved. Routine WinRM administration is a plausible alternative; test a source-host process record. |
| RS-08 | **Port lead; low-confidence WinRM candidate.** Port 5986 and HTTPS lack a visible management clue. An approved HTTPS management endpoint is plausible; test destination service inventory. |
| RS-09 | **Inconclusive.** There is no standard port, decoding, setup, or reply. Context and Decode As are not proof. A routine application connection to a custom service is plausible; test a source-host process record. |

## Short-response key

1. Capture point, time window, host-address mapping, and any missing traffic direction.
2. It shows packets decoded as RDP or SSH regardless of default ports. Filtering hides rather than deletes packets; matches do not prove completed access, and no matches do not rule out either service.
3. RDP can establish related UDP traffic, so a TCP-only view may miss part of the relationship.
4. Strings from both peers show the recognizable SSH identification exchange; port 22 is only a lead.
5. No. Decode As is an interpretive override, not proof; missing setup and replies leave uncertainty.
6. The HTTP request/reply and `wsman` prefix suggest WinRM. They do not prove a completed task, exact work, user, or authorization.