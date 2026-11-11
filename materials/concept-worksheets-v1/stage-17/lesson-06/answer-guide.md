# Answer Guide — Structural Reasoning Key

No investigative answer exists because the lesson supplies no case evidence.

## Checkable expected result
- No packet, host, address, account, operation, or timestamp is invented.
- The packet table contains no case-data row.
- Claim levels are marked `not provided by lesson` or `unresolved`, not promoted from one another.
- The hypothesis retains placeholders and is labelled a plan for a finding.
- Any evidence request names one owner, a bounded window, source and targets, one question, and authorization context.

## Reasoning key
1. **Visibility:** Q1 should state that the capture point and gaps bound conclusions. Missing traffic or an empty packet list does not prove an action did not occur elsewhere.
2. **Identity:** Q2 should request time-bounded inventory or address-history evidence. A packet address is not automatically a host identity.
3. **Packet claims:** Q3 must cite source file, frames, direction, operation, and response before claiming an observation. `smb2` decoding does not prove intent or complete coverage. Share access cannot establish transfer, execution, compromise, or lateral movement.
4. **Host checks:** Q4 may name retained 5145 records for share-access comparison and retained 4688, process, or service records for an execution question. Close timestamps alone are insufficient; target, clock, address holder, account, and job context must match.
5. **Alternative explanation:** A deployment, administrator action, or backup is only a possibility. The corresponding approved job or authorization record must match source, targets, operations, and time.
6. **Missing evidence:** `not collected`, `expired`, and `unknown` describe limits; they do not refute the hypothesis.

`Observed` means directly supported by a cited record. `Inferred` means an interpretation requiring testing. `Unresolved` means available evidence cannot decide the claim. Confidence belongs to each claim, not the whole narrative. The completed template does not claim an attacker moved.