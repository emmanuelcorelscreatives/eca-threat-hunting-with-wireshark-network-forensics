# Data dictionary

All CSVs are UTF-8 with headers. Quote fields containing CSV delimiters. UTC timestamps use ISO 8601 with `Z`; windows are `[start,end)`. Empty means **not observed/not established**, never a negative finding.

## `evidence-note.csv`

- `capture_file`: local working-copy filename; `capture_point`: documented collection position, or `unknown` if not established.
- `window_start_utc`, `window_end_utc`: scoped UTC bounds, start before end; `candidate_domain`: exact candidate suffix, such as `edge.academy.test`.
- `query_frame`, `response_frame`: actual decoded positive frame integers; leave either blank without that packet. Never transfer hypothetical CSV row numbers here.
- `visible_requester`, `query_destination`: observed query source and destination IPs; names describe roles only when the capture context supports them. Neither identifies a person or process.
- `query_name`: exact question name; `labels_with_octets`: ordered `label:length|label:length` entries, counting each label’s encoded octets, not the full-name display length.
- `qtype`, `answer_type`: observed DNS type mnemonic or number, e.g. A/1 or TXT/16; `answer_text`: transcribed observed answer, blank without a matching captured answer. Multiple answer records require separate notes.
- `distinct_names`: `|`-separated qualifying question names; `distinct_count`: their nonnegative count within **this** candidate/domain/window/visibility. Normalize case and a terminal dot for deduplication, retain captured spellings in observations, and count repeats once.
- `observation`: packet-supported statement; `hypothesis`: possible meaning; `ordinary_explanation`: testable benign alternative; `attribution_limit`: what the vantage point cannot establish; `next_source`: one useful missing context source; `confidence`: `low`, `medium`, `high`, or `unresolved`, with justification in the note.

## Other resources

`txt-example.csv` has `example_id` (pair key), `record_role` (`question`/`answer`), `time_utc`, `src_ip`, `dst_ip`, `qname`, `rr_type`, and `txt_value` (blank for the question). Its rows are an **independent hypothetical**, not packet-derived logs.

`fixture-spec.json` uses builder version `1`, `synthetic: true`, and ordered `events`. Each event has UTC `timestamp`, `kind` (`dns-query`/`dns-answer`), documentation-network `src`/`dst`, UDP `sport`/`dport`, reserved `.test` `name`, and matching integer `transactionId`. Answer events additionally require documentation-network IPv4 `answer`. This builder hardcodes A questions and A answers; it cannot encode TXT.

Current v2 additions: `fixture-spec-v2.json` and `offline-builder-v2.py` produce `practice-v2.pcap`. Optional qtype defaults to 1; qtype16 uses an ASCII `txt` answer. Ports, transaction, name and reverse tuple bind answers to questions. The original A-only spec/builder/capture and assembly manifest are historical provenance. `decoded-v2.stdout.txt` is CSV despite its log extension. `scoped-verification.json` contains executed scoped records, exact capture SHA and deduplicated names; `verifier-execution.json` records invocation and rejected bad inputs.
