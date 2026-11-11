# Investigation-candidate worksheet

## Exercise context

**Synthetic conditional exercise—not an incident or observed result.** Translate a previously authorized packet observation into a bounded monitoring proposal. The premise may suggest recurring outbound connection starts between a mapped asset and peer. It does not establish the process, user, authorization, purpose, ownership, or maliciousness.

## 1. Packet-supported facts

Observation and source references: ____________________________________

Capture location and time: __________________________________________

Mapped asset and peer: ______________________________________________

How separate connection starts were recognized, without counting packets or retransmissions as new starts:  
____________________________________________________________________

Missing direction, window portions, and other unknowns:  
____________________________________________________________________

## 2. Repeatable source and coverage

Proposed authorized connection-record source: ________________________

Evidence or unknowns about outbound-path and intended-window coverage:  
____________________________________________________________________

Address-translation effects: ________________________________________

Asset/address mapping and applicable period: _________________________

Included connection kinds—attempts, completed exchanges, or another documented subset:  
____________________________________________________________________

### Field dictionary

| Required concept | Illustrative Zeek field or concept | Meaning and check |
|---|---|---|
| Start time | `ts` | First packet the sensor observed; earlier activity may be missed. |
| Connection identity | `uid` | Count distinct connections, not packets. |
| Endpoints | Originator and responder fields | Map asset and peer; fields alone do not prove organizational ownership. |
| Transport | `proto` | Transport-protocol grouping key. |
| Locality | Local-endpoint indicators | May be empty when local-network definitions are not configured. |
| Collection loss | `missed_bytes` | A nonzero value means some content was not observed. |

Equivalent fields and verified meanings for another source: ___________

## 3. Proposal decisions

Population—intended time and mapped assets: __________________________

Grouping—mapped asset, responder, protocol, and window: ______________

- `WINDOW`: unresolved or case support: ______________________________
- `MIN_DISTINCT_CONNECTIONS`: unresolved or case support: ___________
- `INTERVAL_RANGE`: unresolved or case support: ______________________
- `REQUIRED_MATCHING_GAPS`: unresolved or case support: ______________

Verified approved-activity evidence must cover ownership, asset, peer, and schedule. Evidence and exclusion reason:  
____________________________________________________________________

## 4. Non-executable pseudocode

```text
INPUT authorized connection records, asset mapping, approved-activity context
IF required records, coverage, mapping, or observation sufficiency are missing:
  RETURN UNEVALUABLE with missing inputs and visibility limits
KEEP intended time, mapped assets, and original records
DEFINE which connection kinds qualify
GROUP BY mapped asset, responder, protocol, WINDOW
COUNT DISTINCT connection identifiers
SORT distinct starts; COMPARE adjacent gaps with INTERVAL_RANGE
IF count and REQUIRED_MATCHING_GAPS meet case-supported parameters:
  IF ownership + asset + peer + approved schedule are verified:
    RETURN EXCLUDED with reason
  ELSE RETURN CANDIDATE
ELSE RETURN NEGATIVE
```

## 5. Candidate return and self-check

Mapped asset: ______ Peer: ______ Window: ______ Distinct count: ______

Relevant gaps: ______ Supporting identifiers: ________________________

Exclusions checked and reasons: _____________________________________

Coverage and attribution limits: ____________________________________

Packet references, when available: __________________________________

- [ ] The source can observe the behavior.
- [ ] The proposal counts connections, not packets.
- [ ] Exclusions require evidence.
- [ ] Unevaluable is separate from negative.
- [ ] The output preserves investigation context.