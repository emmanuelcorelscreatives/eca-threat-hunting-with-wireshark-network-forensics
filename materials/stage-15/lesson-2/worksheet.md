# Query shape, diversity, and volume

**Hypothesis:** Is the candidate's authored DNS pattern different enough from comparable traffic to warrant a narrower real-case inquiry? This fixture cannot answer whether data left an organization.

1. Record source file: ______; synthetic capture point: ______; covered hosts: ______; half-open UTC window: ______. Work from the supplied verified unfiltered practice.pcap and record its path. Use events.tsv to cross-check decoded values. A real case needs its own confirmed source: `192.0.2.10` is illustrative, not a universal host identifier. At a shared resolver or behind translation, check attribution before using a source filter.
2. In Wireshark use `dns && dns.flags.response == 0`, then, for this inventory-confirmed candidate only, `dns && dns.flags.response == 0 && ip.src == 192.0.2.10`. Record filters and coverage. Inspect `dns.qry.name`, optionally `dns.qry.name.len`, and `dns.qry.type`. Apply the queried-name field as a column using **Analyze → Apply as Column**; retain packet time and frame references. If a field is not decoded, record the limitation rather than guessing.
3. Count **query messages** and separately count case-normalized **distinct complete names** within each host's assigned group and the same window. Note repeated names. For C01 and T01, calculate dotted ASCII name length, longest label's ASCII-octet length, and its position; do not substitute a whole-name field or treat 63 octets as a suspicion threshold.

| Group | Queries | Distinct names | A/AAAA/TXT queries | Responses: NOERROR/NXDOMAIN | Responses with answers / without | Unpaired queries |
|---|---:|---:|---|---|---|---|
| Candidate C | | | | | | |
| Telemetry T | | | | | | |
| Content D | | | | | | |

4. Switch to `dns && dns.flags.response == 1`. Check `dns.flags.rcode` **and answers**; pair responses to queries using the dictionary. Record both TSV event IDs and the corresponding decoded frame numbers. Contrast C09/C10, C07/C08, and C15. Which examples support concern, and which challenge it? ______
5. DNS statistics summarize message categories, not distinct names; a response-inclusive view is not a query count. If using Distribution statistics, identify field-value frequencies: normalized distribution entropy is **not** character entropy within a label. Compare matched asset roles, capture point, and interval. Separate packet observations from possible explanations and unknown process, user, command, or exfiltration claims. Cache, shared-resolver attribution, incomplete capture, and encrypted DNS are visibility considerations, not observed alternate paths. For a real case, specify the narrow matching resolver-client or authorized endpoint-application records needed: ______. The next lesson considers timing and direction.
For each candidate and control, fill: frame ____; reported name length ____ or unavailable ____; dotted ASCII length ____; longest label octets ____; position from left ____. Investigate actual service ownership and expected host use before applying this authored comparison to a real case: owner ____; source of confirmation ____; expected use ____.
