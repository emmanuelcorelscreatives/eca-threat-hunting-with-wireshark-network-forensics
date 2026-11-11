# Answer Guide

## Baseline checks
The verified synthetic baseline has six DNS packets on a bidirectional client-facing link, not an incident capture or a capture shown in the lecture. The following key applies only to the hash-verified fixture in Setup: confirm each worksheet value in the learner's authorized Wireshark view. The response flag separates queries from responses; match both transaction identifier and question name, and record answer addresses only when answer fields contain them.

| Frame | Sender → receiver | Response flag | Transaction ID | Question name | Answer, if present |
|---|---|---|---|---|---|
| 1 | `192.0.2.10` → `192.0.2.53` | query (`0`) | `0x1001` | `portal.academy.test` | — |
| 2 | `192.0.2.53` → `192.0.2.10` | response (`1`) | `0x1001` | `portal.academy.test` | `198.51.100.20` |
| 3 | `192.0.2.10` → `192.0.2.53` | query (`0`) | `0x1002` | `updates.academy.test` | — |
| 4 | `192.0.2.53` → `192.0.2.10` | response (`1`) | `0x1002` | `updates.academy.test` | `198.51.100.20` |
| 5 | `192.0.2.10` → `192.0.2.53` | query (`0`) | `0x1003` | `portal.academy.test` | — |
| 6 | `192.0.2.53` → `192.0.2.10` | response (`1`) | `0x1003` | `portal.academy.test` | `198.51.100.20` |

1. Decoded queries originate from the synthetic client `192.0.2.10` (frames 1, 3, 5); `192.0.2.53` sends the replies.
2. For example, query frame 1 and reply frame 2 share ID `0x1001` and question `portal.academy.test`; the response flag and reversed endpoints distinguish the reply. The other matching pairs are frames 3/4 (`0x1002`, `updates.academy.test`) and 5/6 (`0x1003`, `portal.academy.test`).

The baseline establishes decoded-DNS field practice only—not compromise, a requesting endpoint for another connection, or a later connection. A valid bounded statement is: **No decoded DNS appears in this capture view during the recorded window.** It does not establish that no lookup occurred.

## Synthetic scenario reasoning key
- **S1:** Conclude only that no decoded DNS crossed the covered client-facing view during that window. Earlier lookup, local cache, an already-known or hardcoded address, encrypted resolution, or another path may remain possible. Resolver cache alone would still normally leave a client-facing exchange on the covered link. Request endpoint resolution records for the window, including application-managed resolution when available.
- **S2:** Conclude only that the upstream view contains no upstream query. It cannot identify a requesting endpoint or exclude a cached resolver answer. Request the receiving resolver's client-facing query/reply record, including client, name, answer, and available cache information.
- **S3:** A client-facing DNS request and reply are observed, but the querying client's relationship to the endpoint of interest and any later connection is unknown. The absence of a corresponding upstream request makes a resolver cache plausible, not proven. Request the receiving resolver's client-facing query/reply record with available cache information for that exchange and window.
- **S4:** HTTPS is observed, but HTTPS alone does not prove DNS over HTTPS. Select one most-discriminating record: either endpoint or application resolver configuration to test whether encrypted resolution was configured, or relevant resolution records to test whether a lookup occurred; do not request both as the worksheet answer.
- **S5:** Port 853 is a clue, not proof of DNS over TLS, and the filter does not find every possible setup. Request endpoint resolver configuration or corresponding resolver records before naming the protocol.

Across the scenarios, keep local cache, resolver cache, previously known addresses, encrypted resolution, and collection gaps separate; apply only explanations that fit the observed view. A local cache alone cannot explain S3's observed client-facing request. Check clock differences and retention before correlating records. If the requested evidence is absent or inconclusive, the conclusion remains inconclusive.