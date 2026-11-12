# Answer guide — supplied synthetic records

For the **core exercise**, the authored CSV design lists I-01 and I-02 as 4769 records for `LAB\svc_maint`, `cifs/fs1.lab.test`, client `192.0.2.17`, with status `0x0`. They represent two synthetic successful request records, **not** verified packet decodes, target access or credential theft. I-03 is authority-side 4776 with workstation `WS17`; it does not name a destination. D-01 and D-02 are nearby synthetic 4624 logon-session records on `fs1.lab.test`. Their source-address and workstation fields are empty; neither is linked to I-03 or a particular packet by these fields or by timing.

The authored host rows are one client Event ID 1 and three client Event ID 3 examples. There are no intermediary process records in this exercise; that is unavailable telemetry, not evidence of no connection. Sysmon Event ID 3 logging is off by default in real deployments. The scenario’s recovery work is a possible ordinary explanation supplied as training context, not independently established approval.

Accept: **observed record** for “I-01 lists a service”; **unsupported** for “the later connection used that ticket” and “credentials were stolen”; **missing telemetry** for the onward leg. A possible relay is an **inference** to investigate, not a conclusion. Even matching packet times, claimed NTLM names, validation and destination logons would not prove one forwarded exchange or one human operator. LDAP-over-TLS encryption alone cannot show whether channel binding was checked; ask for target settings and appropriate server records.


## Complete keyed timeline

All times below are UTC on 2025-01-16. Keep tracks separate; ordered timestamps are not proof of causality.

| Track | Record | Time | Supplied observation |
|---|---|---|---|
| Identity/DC | I-01 | 12:00:01.200 | 4769, LAB\svc_maint, client 192.0.2.17, cifs/fs1.lab.test, status 0x0, encryption 0x12 |
| Identity/DC | I-02 | 12:00:03.100 | Same illustrated request attributes as I-01; 1.900 seconds later |
| Identity/DC | I-03 | 12:00:08.500 | 4776, LAB\svc_maint, source workstation WS17, status 0x0; destination not supplied |
| Destination/fs1 | D-01 | 12:00:05.750 | 4624, type 3, Kerberos, logon ID 0xB10; source address/workstation empty |
| Destination/fs1 | D-02 | 12:00:09.100 | 4624, type 3, NTLM, logon ID 0xB11; source address/workstation empty |
| Host/ws17 | H-01 | 12:00:00.300 | Sysmon 1, local PID 5000, synthetic_recovery_app |
| Host/ws17 | H-02 | 12:00:00.900 | Sysmon 3, same illustrated PID, 192.0.2.17 → 192.0.2.20:88 |
| Host/ws17 | H-03 | 12:00:05.000 | Sysmon 3, same illustrated PID, 192.0.2.17 → 198.51.100.30:445 |
| Host/ws17 | H-04 | 12:00:08.000 | Sysmon 3, same illustrated PID, 192.0.2.17 → 192.0.2.40:445 |

There are 3 identity, 2 destination and 4 host rows, 9 total. The supplied window is 12:00:00 through 12:00:12 UTC. Zero host offsets are authored assumptions, not measured synchronization. PID 5000 is a local illustration, not a globally unique process or verified cross-host identity. Event 1 adds creation context; enabled Event 3 logging can add process-to-connection context. Missing events may reflect logging, collection or coverage gaps. A destination type-3 logon is a network logon; these empty source fields and separate host-local logon IDs cannot join it to a particular validation or packet.

## Example provisional handoff

Hypothesis: investigate whether repeated service-ticket requests and subsequent illustrated network activity reflect recovery work or unexpected authentication through an intermediary. Basis: I-01/I-02, H-02/H-03/H-04, and D-01/D-02 are authored records on separate tracks. No packet capture or intermediary onward/process telemetry is supplied; the hypothetical client-link vantage would not cover gw1 onward traffic. Confidence is limited: neither relay, stolen credentials, ticket use nor unauthorized access is established. SYN-MAINT-042 offers an ordinary explanation that needs independent confirmation.

Request dc1 4769 records for LAB\svc_maint and cifs/fs1.lab.test and 4776 records for WS17 around 12:00:00–12:00:12 UTC on the exercise date, expanding only for measured clock offsets: clarify request and validation details. Request fs1 4624 records with complete available source/workstation fields and authentication package to assess destination logons, without assuming a join. Request client and gw1 process creation/network telemetry, when collected, over the same bounded window to test process-to-connection and onward-path hypotheses. Ask asset owners for client/gw1 roles and independent maintenance records to test approved recovery context. Request capture-point, clock, address/NAT mapping and collection-loss information to assess visibility. If investigating LDAP-over-TLS channel binding, request target configuration and appropriate server validation records; encryption alone cannot show the check occurred. Outside a Windows domain use the equivalent trusted identity and endpoint sources.

For the optional learner-selected capture, accept only answers grounded in that actual file with its provenance and coverage. No fixed frame numbers or packet findings are keyed here. An unattempted assignment is correctly marked no supplied capture, not a failed or completed packet demonstration.
