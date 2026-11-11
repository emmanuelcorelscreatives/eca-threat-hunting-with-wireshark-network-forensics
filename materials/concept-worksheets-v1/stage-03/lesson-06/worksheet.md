# Evidence intake note — worksheet

**SUPPLEMENTAL SYNTHETIC PRACTICE — NOT CASE EVIDENCE.** `TRAINING-NOFILE-001` is a training identifier, not a case reference. At 2025-02-18 16:00 UTC a training portal assigned ANALYST-01 the request: determine whether synthetic host LAB-WS-17 contacted documentation address 203.0.113.77 between 2025-02-18 14:00 and 14:15 UTC. No packet capture, supplier or collector statement, authorization or case reference, collection metadata, custody log, filename, file hash, or working copy accompanies the request.

**Instructions and field schema.** Copy this worksheet. For each blank, enter `value | class and specific source | status`. Classes: `R` = request; `O` = inspected-file observation; `C` = attributed collector report; `H` = documented handling; `U` = unresolved. Statuses: `recorded` requires a source; `unknown` or `not verified` identifies unsupported facts; `pending` applies to an unmade or unchecked working copy; `none recorded` describes undocumented actions, not proof that nothing happened earlier. Leave unsupported file observations blank. Do not treat request delivery as a packet-file handoff.

## Fillable intake note

1. **Question and origin:** question ___; request source, assignment time and zone ___; assigned analyst ___; file supplier ___; collector and stated method ___; authorization/case reference ___; stated reason and reference for file handoff ___.
2. **Scope:** stated observation point and source ___; covered systems/segment and source ___; requested interval ___; collector-stated collection window, time zone and source ___; collection filter and source ___; visibility of both directions and source ___; routing viewpoint and source ___.
3. **Original:** exact received filename and location ___; observed size and format ___; preserved-original location and access restriction ___; SHA-256 value, supplier or checker, method and time ___; unresolved identity/integrity gaps ___.
4. **Handling:** receiving analyst and file receipt time/zone ___; each known transfer (item, sender, recipient, time/zone, reason, handoff reference) ___; custody gaps ___; working-copy identity, location and verification status ___.
5. **Changes:** each export, selection, conversion or redaction (input, action, resulting file/location, exclusions, reason, hash and checker/time) ___; pre-receipt changes ___.
6. **Inspection:** inspected file and available metadata/interface details ___; first/last packet times ___; captured count ___; analysis display selection and displayed count ___; drop count and source ___; payload visibility ___.
7. **Boundary:** confirmed limits and source ___; unresolved visibility questions ___; each gap’s effect on the claim and another record that could resolve it ___; contact/no-contact conclusion boundary ___; next request ___.

## Practical questions

- Does the requested interval verify the collection window? Why? ___
- Can a matching hash prove capture completeness or custody? Why? ___
- Can a later display filter recover traffic excluded at collection? ___
- If viewpoint or directions are unknown, what can a no-contact claim say? ___