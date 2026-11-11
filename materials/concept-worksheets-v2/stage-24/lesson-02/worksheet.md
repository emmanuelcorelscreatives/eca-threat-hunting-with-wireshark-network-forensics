# Evidence Intake Worksheet

**Synthetic exercise — blank structure only, not a captured or observed incident.** Enter only authorized, supplied facts. Preserve originals and analyze separate copies. Use **not yet checked**, **not available**, or **unknown** for missing values; record zero only when measured or documented.

Each section maps to one workbook sheet.

## 1. Question-Window

- Authorized question: ______________________________
- Systems and records permitted: ______________________________
- Observation that matters: ______________________________
- Brief, working-hypothesis, and supplied business-context basis: ______________________________
- Provisional start, end, and time basis: ______________________________
- Portion testable with current coverage: ______________________________
- Uncovered portion and resulting limit: ______________________________

## 2. Source

Repeat only for supplied items.

- Source ID; type; original identity: ______________________________
- Supplier; authorized purpose: ______________________________
- Original location; access or handling rule: ______________________________
- SHA-256; checker; check status: ______________________________

## 3. Derivative

- Derivative ID; immediate parent Source ID or Derivative ID: ______________________________
- Kind: working copy / redaction / export / saved-comment change / other
- Change and purpose: ______________________________
- Location; SHA-256; checker: ______________________________
- Access or handling rule: ______________________________

## 4. Capture-Coverage

- Source or Derivative ID; verified working-copy path: __________________
- Capture File Properties SHA-256 (if displayed, for the opened working copy); independently checked working-copy SHA-256; agreement or discrepancy: __________________
- Displayed size; format; captured packet count; displayed packet count: __________________
- Capture point; documented interface and address mapping: __________________
- Snapshot length; recorded drops; both-direction evidence: __________________
- Documented collection filter or collection notes: __________________
- Earliest and latest packet timestamps: __________________
- Documented collection start and stop: __________________
- Read-filter state; display-filter state: __________________
- Remaining metadata uncertainty and collection-owner question: __________________

## 5. Time-Basis

Question-window lane — start; end; basis: ______________________________

Repeat for each source lane; for a capture, enter packet bounds and any documented collection period on separate lanes:

- Source or Derivative ID; coverage type (packet bounds / documented collection period / other source); start; end: ______________________________
- Original time zone; Wireshark display setting: ______________________________
- Timestamp precision; accuracy evidence: ______________________________
- Measured offset, if any; uncertainty: ______________________________

## 6. Gap-Request

- Gap ID; affected question: ______________________________
- Missing observation; possible reasons: ______________________________
- Effect on confidence: ______________________________
- Specific record or collection detail requested: ______________________________
- Case owner; retention concern; status: ______________________________

## Field Key

- **Packet bounds:** earliest and latest timestamps, not first and last stored packets.
- **Collection period:** start and stop only when documented; keep separate from packet bounds.
- **Question window:** comes from the case question and context, not an unexamined packet.
- **Snapshot length:** per-packet capture limit.
- **Precision:** timestamp detail. **Accuracy:** whether the clock was right.
- **Measured offset:** record only supported measurements; never guess a correction.
- **Possible reason:** an open possibility, not a finding.

## Practical Review

1. Why must intake filters remain empty?  
   Answer: ________________________________________________
2. Can a reviewer link every derivative to its preserved original and checked hash?  
   Answer: ________________________________________________
3. What overlap supports a limited check, and what interval remains uncovered?  
   Answer: ________________________________________________
4. What relevant path could the recorded vantage point not observe?  
   Answer: ________________________________________________
5. If authorized case context allows a gap to be ranked, which targeted request would address the highest-priority gap? Otherwise, why can't one be ranked?  
   Answer: ________________________________________________