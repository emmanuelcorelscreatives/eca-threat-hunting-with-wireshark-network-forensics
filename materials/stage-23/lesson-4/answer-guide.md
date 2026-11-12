# Verified instructor key: synthetic offline exercise

These are measured decoded packet fields and evaluated authored proxy records for this exact synthetic kit. Labels and approval context remain authored scenario ground truth. There is no historical incident, production proxy collection, completed data export, malicious process identity or learner-own-capture claim.

See expected-results.json for exact capture hashes, epoch timestamps, original filenames, both frame namespaces, log IDs, case filters and rationale. `verified-http-fields.stdout.txt` actually decodes GET, request path and HTTP 200; `execution-proof.json` binds commands and actual extraction. Each extracted original has nine frames, request 4 and response 5. In combined practice.pcap the request/response pairs are 4/5, 13/14, 22/23, 31/32 and 40/41 respectively. Never cite a combined frame as though it were from an extracted original.

| Case | Log | Packet path | Proposal alert units | Outcome and reason |
| --- | --- | --- | --- | --- |
| C01 | R01 | /stage23/export.txt | 1 | Hit: authored unauthorized label and matching required record |
| C02 | R02 | /stage23/readme.txt | 0 | Correct non-alert: authored permitted read, path differs |
| C03 | R03 | /stage23/export.txt | 1 | False positive: matching condition but authored approved-backup context |
| C04 | R04 | /stage23/export.csv | 0 | False negative: observable required record exists but fixed exact path excludes it |
| C05 | absent | /stage23/export.txt | unscored | Coverage exclusion: packets cannot replace the deliberately unavailable proxy record |

Totals: five cases, four scored, one excluded; one hit, one correct non-alert, one false positive, one false negative, two alert units. C05 is not a false negative. No rates or general network effectiveness are inferred. Matching records are one per matching source/minute here; TCP packets are never counted as repeated alerts. All five have observed bidirectional synthetic packets in the case window; that observation does not establish all production collection properties.

Question each label independently. If approval context or required source cannot be trusted, withhold the category and request context or telemetry. The false-positive alternative is an approved backup, supported only by the supplied authored label. For C04 the miss is the path restriction, not missing telemetry. For C05 request a verified proxy record or collection-health evidence before scoring. The student matrix deliberately remains blank in observed fields.
