# Choose the Durable Behaviour to Monitor

**Threat Hunting with Wireshark Course — Stage 23, Lesson 1**  
**Instructor: EMMANUEL CORELS**

## Purpose and boundary

Choose a behaviour that remains worth reviewing when a peer address changes, and identify whether named telemetry can actually show it across the intended asset group and observation window. Keep packet-supported observation, interpretation and unknowns separate. Recurring outbound communication is not proof of malicious activity or a command channel.

The narrated incident and proposed course cases were not supplied. This kit is separate, clearly labelled **synthetic Academy coursework**, not a reconstruction of that incident or a completed learner-owned investigation. The lecture is unchanged. Inspect only captures you are authorized to use.

## Learning route

1. Read [setup.md](setup.md) for the evidence boundary and native Wireshark workflow.
2. Complete **all** collection fields and tasks in [worksheet.md](worksheet.md): conversations, underlying packets, graph windows, DNS, byte meanings, indicator versus durable candidate, claim-to-source matching, coverage and alternative explanations.
3. Use [checker-usage.md](checker-usage.md) for optional integrity-checked rebuilding and independent raw-checker interpretation. Rebuilding is not necessary to inspect the supplied capture.
4. Compare your work with [answer-guide.md](answer-guide.md) and [DATA_DICTIONARY.md](DATA_DICTIONARY.md), alongside the decoded, raw and role-limited native evidence described in the setup. Historical pending statements refer to their older saved snapshots; a checker pass does not override evidence limits.

The kit supplies `practice.pcap`, `asset-inventory.csv`, `executed-fixture-spec.json`, its assembly-identical alias `fixture-spec.json`, `offline-builder.py`, `check_capture.py`, saved command outputs, raw reports and reviewed native views. No obsolete draft PCAP alias or builder filename is required as a duplicate artifact. No verified public repository URL or download branch is supplied.

## What you must produce

Complete the existing worksheet rather than inventing a case finding. Include capture identity and SHA-256, authorization and collection notes, inventory-defined group, window, supporting frames, source and peer ports, event and retry rules, graph settings, DNS references, telemetry fields, alternatives, blind spots and specific evidence requests. State separately which facts you inspected yourself and which come from saved evidence.

A defensible candidate asks whether a defined asset group initiates recurring outbound connections worth contextual review even when peers change. Test both questions: would the behaviour still matter if the peer changed, and can the named recorded data show it across the intended population and window? If either is uncertain, narrow or hold the claim.

For future learner-owned work, obtain permission before collection or inspection. Use a suitable capture and a separate collection record; preserve an untouched original where permitted. Record provider, observation point, interface, UTC window, clock information, capture/read filters, drops or gaps, directions, asset owners, handling limits and working-copy hash. Repeat the worksheet against that capture's own frames. This remains future learner work, not something completed by this kit.

## Status

The supplied evidence includes a matching fresh rebuild, existing-output refusal proofs, independent decoded flags and raw-byte checks, and exact role-limited native PNG approvals. It does not establish complete sensor coverage, authorization, process identity, application content or an original-case finding. New exact-pass native views expand all 28 TCP frames and four DNS frames, show graph windows at 60 and 120 seconds and selected underlying frames 16 and 25, and preserve host-platform evidence identifying Ubuntu 24.04.5 LTS with Wireshark 4.4.0. See [native-validation.md](native-validation.md) for a reproducible frame-specific walkthrough and limits. The supplied current-kit-inventory.json binds the final saved files; its own recursive hash is intentionally omitted. Preserve historical manifests unchanged and refresh the current inventory after later edits.

These guides require a separate complete independent review before publication. Public placement, publication, main-course visual/render approval and a completed learner investigation are not claimed. Carry the supported observation and visibility limits into **Write a Reusable Hunt Playbook**.
