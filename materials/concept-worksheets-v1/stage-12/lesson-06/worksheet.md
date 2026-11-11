# Worksheet — Credential-Risk Escalation

## Scope and task

> No Project 4 capture was supplied so this note contains no findings.

This is a no-case exercise, not a captured incident. Do not create packets, assets, accounts, times, outcomes, or mappings. An authentication packet cannot prove account takeover. Use `unresolved` whenever supplied material cannot establish a requested fact.

## 1. Lead with the decision

Write one bounded question asking whether authentication activity, if established, warrants a credential-misuse investigation or could reflect an approved service or outdated credential.

**Decision question:**  
____________________________________________________________________

**Requested interim action:**  
____________________________________________________________________

## 2. State capture scope

Fill only from evidence; otherwise write `unresolved`.

| Field | Answer |
|---|---|
| Original capture or case identifier | |
| Collection point and traffic directions | |
| Covered start and end | |
| Time zone or convention | |
| Timestamp source | |
| Clock uncertainty | |
| Collection gaps | |
| Edited or merged-copy disclosure | |

## 3. Keep evidence sources separate

> Without a capture or identity excerpts, leave the table empty.

**Packet evidence — header only**

| Capture ID | Copy disclosure | Original frame | Timestamp and convention | Filter or starting point | Source | Destination | Decoded details | Supported label |
|---|---|---|---|---|---|---|---|---|

**Asset mapping — header only**

| Observed address | Peer role | Mapping source | Valid period | Assignment uncertainty | Account-link status |
|---|---|---|---|---|---|

**Separately sourced identity evidence — header only**

| System | Record ID | Time | Account | Source | Destination | Event type | Result | Correlation basis |
|---|---|---|---|---|---|---|---|---|

Field rules: cite the original frame and disclose edited or merged copies. Use only mappings valid for the covered period. A captured endpoint is not necessarily an account user. Identity claims require their own records. Label a request, response, retry, or error only when its source supports that label. A screenshot alone cannot verify it.

## 4. Analyze without an attack verdict

1. Which account, if any, links to an exchange? **Answer:** __________
2. Were attempts rejected, accepted, or impossible to classify? **Answer:** __________
3. Which destination recorded the activity? **Answer:** __________
4. Was the use expected for that account and service? **Answer:** __________
5. Is an account-to-host-and-time link independently supported? **Answer:** __________

| Competing explanation | Evidence for or against | Assessment |
|---|---|---|
| Credential misuse | | |
| Service retries using an outdated credential | | |
| Approved maintenance | | |

| Claim | Confidence | Evidence and limitation |
|---|---|---|
| Captured authentication-related traffic | | |
| Initiating person or process | | |
| Account misuse or takeover | | |

Explain why `kerberos || ntlmssp || ldap` can narrow captured, decoded traffic but cannot restore missing traffic or establish an account, and why it misses authentication traffic decoded as other protocols:  
____________________________________________________________________

**Evidence-based urgency and retention concern:**  
____________________________________________________________________

## 5. Request the missing evidence

Assign each request a priority, owner, and answerable question. Cover identity records and retention, original capture scope, process or retry context, maintenance, address assignment, and final review.

| Priority | Owner | Question | Decision affected |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |

**Decision owner:** ____________________

## Self-check

- Every packet claim points to its original capture and frame.
- Every named asset has a period-valid mapping.
- Every identity claim points to a separate record.
- Network peers, devices, and accounts remain distinct.
- Unseen systems are not called unaffected.
- Password theft, pass-the-hash, and takeover are not inferred.