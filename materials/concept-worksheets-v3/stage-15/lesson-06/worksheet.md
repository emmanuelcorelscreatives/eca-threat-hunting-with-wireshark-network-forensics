# Channel investigation worksheet

**Synthetic exercise: no capture is loaded and no incident findings are supplied.** With an authorized capture, begin with the display filter `dns`; narrow by host, name, and time while retaining queries and responses. Without packets, `dns` is an example, not an executed pivot.

## Identity and visibility

- Candidate host and role, protocol, expected service: _____
- Actual capture identifier; original or working copy; original identifier and frame mapping if copied: _____
- Collection point, start/end window, truncation, missing directions, gaps, stopping point: _____
- Client-facing or resolver-side only? Are responses visible? Could caching explain an absent upstream lookup? _____
- What does an empty packet list establish about traffic? _____

## Independent evidence chain

For each row, identify its source. Cite original frames for packet observations, plus the filter or pivot that finds them again. If using I/O Graphs or Conversations, record the interval or grouping and check the underlying packets.

| Check | Source; original frames; filter/pivot; interval or grouping | Observation and visibility limit | Status | What it supports; plausible benign alternative |
|---|---|---|---|---|
| Structure | _____ | _____ | _____ | _____ |
| Timing | _____ | _____ | _____ | _____ |
| Asset context/control | _____ | _____ | _____ | _____ |

- **Structure:** Label length, changing subdomains, record types, answers and response patterns; unique names or retries? _____
- **Timing:** Compare successive request starts. What span, clusters, repetition, host activity, and capture end can be checked? Graph interval; conversation grouping and peers: _____
- **Context/control:** Authorized inventory or service-owner source, approved application, same-role host and comparable period; approved telemetry or content-delivery similarities **and differences**, or `unknown`: _____
- **Other protocols, if relevant:** What ICMP diagnostic or unexpected-port application behavior could explain the exchange? What encoded training content is actually visible? _____

A resolver’s upstream request does not identify one client. A port, dissector choice, or encoded-looking content does not establish application, intent, confidentiality, or data loss.

## Judgment and next question

- Observed packet exchanges or supplied-record facts: _____
- Inferred meaning **and** another possible explanation: _____
- Not established—for example, originating client, purpose, encrypted content, sensitive data, or its unique amount: _____
- `suspicious` / `explained` / `unresolved`; reason and strongest available evidence against that choice: _____
- Confidence in occurrence: _____; confidence in purpose: _____; precise limits and evidence that would change each: _____
- **One targeted request**, its provider, and how the answer could change the disposition: _____