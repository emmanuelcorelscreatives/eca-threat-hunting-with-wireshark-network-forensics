# Answer Guide

**Synthetic reasoning key—not case findings.**

| Conversation | Expected reasoning |
|---|---|
| KRB-01 | K1 asks the authentication service for initial credentials; an AS-REP or error may follow. K3 requests credentials for access to a service; it may receive a reply or error. W ↔ D is observed and expected under the synthetic map. K4 does not show S receiving an AP-REQ because AP-REQ belongs to the client-to-service exchange. Ordinary domain ticket activity might fit. Inspect coverage and later client-to-service traffic rather than filling the gap. |
| NTL-01 | Type 1 is NEGOTIATE, type 2 is CHALLENGE, and type 3 is AUTHENTICATE. W ↔ S is observed and fits the mapped file-service relationship. AUTHENTICATE establishes only that the protocol message was sent. It does not identify the person, explain why NTLM was selected, establish authorization, or prove theft or compromise. The next action is to inspect the surrounding application conversation and relevant policy or host context. |
| LDP-01 | L1 is an authentication bind; L2 states that the corresponding bind operation succeeded in that session. L3 requests directory entries and is not another login. C ↔ D is observed and expected under the map. The response must correspond by session and message ID. After StartTLS, ordinary capture visibility may not expose protected content. Bind success does not prove account ownership or authorization. |

## Question checks

1. AS-REQ concerns initial credentials; TGS-REQ concerns credentials for a service; AP-REQ is client-to-service. K4 alone proves no AP-REQ delivery.
2. Expected NTLM mapping is 1/NEGOTIATE, 2/CHALLENGE, 3/AUTHENTICATE. Actor and compromise conclusions remain unsupported.
3. Bind authenticates; search requests entries. L2 establishes session bind success only. L4 limits later content visibility.
4. Check capture point, time window, direction, and decoding. A missing reply is an evidence gap, not proof of no reply.
5. A role-consistent protocol exchange can be ordinary workflow. Packets and role maps alone do not establish who acted, whether activity was approved, or whether an account was compromised.

## Checkable totals

Expected: 12 exercise records, three conversations, four records each, and zero acceptable conclusions asserting a person, authorization, credential theft, or compromise.