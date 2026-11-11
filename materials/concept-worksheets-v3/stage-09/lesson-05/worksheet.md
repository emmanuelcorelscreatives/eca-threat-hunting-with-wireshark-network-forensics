# Missing DNS and Encrypted Resolution Worksheet

## A. Synthetic baseline observation
The repository baseline is synthetic practice data, not a captured incident. Complete this section only from your authorized working copy.

**Source file:** ____________________  
**Capture point:** ____________________  
**Start/end:** ____________________  
**Directions/interfaces covered:** ____________________

Apply `dns`. Do not infer that every packet necessarily decodes as DNS.

| Frame | Sender → receiver | Query/response from flag | Transaction ID | Question name | Answer, if present |
|---|---|---|---|---|---|
| ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ |

1. Which senders originated decoded queries?  
   **Answer:** ________________________________________________
2. Demonstrate one query/reply match using transaction identifier and question name.  
   **Answer:** ________________________________________________
3. What can this baseline establish about a later endpoint connection?  
   **Answer:** ________________________________________________
4. Write a bounded statement for a file in which `dns` shows nothing.  
   **Answer:** ________________________________________________

## B. Synthetic exercises
All five scenarios below are invented exercises, not incidents or observed results.

- **S1:** A bidirectional client-facing view covers the connection window. The endpoint connection appears, but decoded DNS does not.
- **S2:** An upstream-only resolver view contains no upstream query during the covered window.
- **S3:** A client-facing DNS request and reply appear, but the covered upstream view has no corresponding request. The querying client's relationship to the endpoint of interest is unspecified; no link to a later connection is established.
- **S4:** Only an HTTPS connection appears near the endpoint connection; protected contents and endpoint configuration are unavailable.
- **S5:** A TCP connection involving port 853 appears; payload confirmation and configuration are unavailable.

For each scenario, state only what the view establishes, list remaining uncertainty, and request one record most likely to distinguish explanations.

| ID | Bounded conclusion | Possible or unknown explanations | Next record and why |
|---|---|---|---|
| S1 | __________________ | __________________ | __________________ |
| S2 | __________________ | __________________ | __________________ |
| S3 | __________________ | __________________ | __________________ |
| S4 | __________________ | __________________ | __________________ |
| S5 | __________________ | __________________ | __________________ |

## Defensible-note template
**Observed transactions/connections:** __________________________  
**Covered point, path, directions, and time:** ___________________  
**Unseen paths/times:** ________________________________________  
**Unresolved explanations:** ___________________________________  
**Requested record:** __________________________________________

Do not treat a nearby query or Wireshark hostname label as proof of connection linkage. Record exact frames, endpoints, and times only when they exist in your source.