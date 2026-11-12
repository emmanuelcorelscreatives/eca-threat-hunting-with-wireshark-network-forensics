# Verified supplemental fixture results

The actual supplied practice.pcap was built offline, independently decoded row by row with TShark and rebuilt byte identically. execution.json records 43 reconciled messages and no malformed frames. These are synthetic fixture observations, not historical case findings.

| Group | Queries | Distinct complete names | Query types A/AAAA/TXT | Responses NOERROR/NXDOMAIN | Answers A/TXT; no-answer responses | Unpaired queries |
|---|---:|---:|---|---|---|---:|
| C | 8 | 5 | 3/2/3 | 6/1 | 2/2; 3 | 1 |
| T | 7 | 5 | 3/2/2 | 7/0 | 3/2; 2 | 0 |
| D | 7 | 6 | 4/2/1 | 7/0 | 4/1; 2 | 0 |

Executed cross-check: 22 queries, 21 responses; 20 NOERROR and one NXDOMAIN response. There are 14 responses with one authored answer each, seven without answers, and one query without an included response. These figures cover **only** the three assigned groups in the specified minute, not all activity by those devices.

C01/C02 and C13/C14 repeat one complete name; C03/C04 and C05/C06 repeat another. C01's first label is observed as 41 ASCII octets at position one; its dotted ASCII name is 57 characters. T01's first label is also 41 octets at position one; its dotted name is 60 characters. Neither dotted length is a claimed `dns.qry.name.len` display value. C09/C10 is observed as NXDOMAIN without an answer; C07/C08 is NOERROR without an answer. C15 has no authored response: do **not** call it NXDOMAIN or resolver failure. T01/T02 challenges a claim that a 41-octet label is candidate-specific; D has greater observed fixture name diversity, and both controls include TXT questions. Event IDs are **not frame references**. Frame mappings: C01/C02 = 1/2; C13/C14 = 37/38; C03/C04 = 7/8; C05/C06 = 13/14; C09/C10 = 25/26; C07/C08 = 19/20; T01/T02 = 3/4. C15 is frame 43 with no captured response. The decoded whole-name field for frames 1 and 3 is respectively 57 and 60 in this recorded build; the longest first label is 41 octets in both.

A defensible practice interpretation is that these measurements could prompt investigation, not establish a tunnel, application identity, commands, or exfiltration. In a real investigation, request narrowly scoped resolver records linking client and query or authorized endpoint records identifying the application for the same window. No real service ownership or case evidence is supplied.