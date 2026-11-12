# Role-mapping worksheet

Hypothesis: time-matched inventory records can propose roles for addresses observed in a capture; packet addresses alone cannot confirm asset ownership.

1. Record the examined file, actual UTC packet bounds, observation-point record and missing collection details. The supplied context is synthetic metadata, not a measured collector report.
2. Clear display filters and inspect IPv4 Endpoints. Record all eight observed addresses and frame references in the CSV. For this supplied file there are no IPv6 endpoints. Do not count TCP/UDP or Ethernet rows as extra verified devices.
3. For each address compare packet time with every inventory interval `[valid_from_utc, valid_until_utc)`. Blank dates establish no coverage. In `inventory_record_ids`, `inventory_sources` and `proposed_roles`, use semicolon-separated entries in matching order to preserve multiple records, including both conflicting records. A role is supported only within this authored scenario when an applicable record is unconflicted; undated plausible records are provisional; incompatible applicable records are conflicting; missing capture-time support is unknown.
4. Retain address reassignment, stale records, misleading names and observation-point visibility as alternatives. Name the exact next record that could resolve uncertainty, and ground confidence in those records. Do not classify any peer as anomalous or malicious.
5. Compare with the checked answer guide after completing the sheet. Which inventoried asset is absent, and why does absence from this short file establish little? Explain why a current-only record, a dated assignment gap and overlapping conflicting records need different follow-up.

For real work, leave identities unresolved until authorized dated records arrive. This exercise does not establish real owners or approved functions. The next lesson's Protocol Hierarchy task does not replace this role-mapping task.
