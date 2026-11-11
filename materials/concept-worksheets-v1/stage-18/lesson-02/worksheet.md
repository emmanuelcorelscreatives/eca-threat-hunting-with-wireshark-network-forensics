# Worksheet — Encrypted Remote-Access Limits

> **Synthetic exercise:** The following is a fictional intake note, not captured packets or an observed incident. Every value is an unverified claim or stated availability status.

## Fictional intake card and data dictionary

| Field | Supplied value | Meaning |
|---|---|---|
| Claimed candidate | 192.0.2.10 to 198.51.100.20 TCP/22 | Asserted endpoints and port |
| Claimed period | 2025-03-04 09:10–09:12 UTC | Period attributed by the note |
| Claimed collection point | client-side span | Asserted observation location |
| Stated sensor window | 09:11–09:12 UTC | Only stated collection interval |
| Direction completeness | unknown | No assurance that both directions exist |
| Source capture | not supplied | No packets are available for corroboration |
| Host authentication and activity records | not supplied | No host outcome or activity evidence |
| Approval context | not supplied | No owner, maintenance, or access approval evidence |

## Exercises

### 1. Unloaded Wireshark

Confirm: no capture or live collection was used. What packet finding can be reported after entering `ssh` and `rdp`?

____________________________________________________________________

### 2. Assess the intake

Which claims can be corroborated without the source capture? Explain how the collection point, shorter sensor window, and unknown direction completeness would limit any later review.

____________________________________________________________________

____________________________________________________________________

### 3. Conditional pivot

For a future authorized capture, consider:

`ip.addr == 192.0.2.10 && ip.addr == 198.51.100.20 && tcp.port == 22`

Why would this identify candidates rather than prove authentication? Why are `ssh` and `rdp` not exhaustive?

____________________________________________________________________

### 4. Keep claims separate

For each column, enter available evidence or an explicit open question.

| Network exchange happened | An account signed in | Organization approved access |
|---|---|---|
| ____________________ | ____________________ | ____________________ |

What separate evidence would address post-access activity?

____________________________________________________________________

### 5. Conditional protocol questions

**Synthetic hypothetical A:** If SSH protocol identification were visible, what would and would not follow?

____________________________________________________________________

**Synthetic hypothetical B:** If an RDP request exposed client-supplied `mstshash`, what would and would not follow?

____________________________________________________________________

### 6. Investigative note

Write a short note naming the missing source capture and collection limits, considering routine administration, stating uncertainty, and requesting the specific host or approval evidence needed next.

____________________________________________________________________

____________________________________________________________________