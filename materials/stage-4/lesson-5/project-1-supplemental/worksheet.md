# Project 1 worksheet — hypothesis, packets, limits

**Scope:** Use this sheet with the labelled synthetic `practice.pcap` now, or with the authorized **narrated-case pack only when it exists**. Keep those investigations separate. The narrated case has no supplied capture, asset list, activity note, or solution: leave its packet cards empty and its outcome undetermined until real materials arrive. Work offline on a copy; do not edit packets to improve a story. The bounded Linux GUI instructions have now been checked as listed in `native-validation.md`; no Windows execution is claimed.

## 1. Intake and prediction, before opening the packet list

- Track (synthetic practice / supplied real case): ____; authorized original and **opened working-copy** filenames and hashes if available: ____; sanitization or other changes affecting references: ____.
- Asset-list source, workstation ID and IPv4 mapping **valid during the relevant window**: ____. If ownership changes or cannot be confirmed, request the mapping rather than assign an address silently.
- Activity-note source, its stated time window **and time reference**, listed destination(s), expected direction and visible protocol: ____. Does it assert an exhaustive destination set? ____.
- Predict what timing, peer, direction, and visible exchange would support scheduled software activity: ____. What would weaken it? ____. Give an alternative legitimate explanation and evidence that could distinguish it: ____. An unfamiliar peer and timing near a schedule prove neither hostility nor approval.

## 2. Coverage before conclusions

- From the working file’s Capture File Properties or recorded CLI output, first and last **packet** times, format/precision, and reported collection metadata: ____. Source of each value: ____.
- Viewer time display versus the note’s reference; clock accuracy/offset known or unknown: ____. Collector placement, unobserved paths, and beginning/end outside this file: ____. Keep the candidate’s stated range inside the observed packet span; a note’s wider window is not capture coverage.
- Initial full packet view checked: ____. In Conversations, was a display filter active **in that view**? ____; endpoint pairs, starts, durations, counts, and traffic directions useful for locating—but not identifying the purpose of—the session: ____. Do not select a peer just because it is busiest.

## 3. Locate and return to the candidate

Candidate’s **source file**: ____; why this is the workstation session in the question rather than a merely plausible pair: ____; addresses, ports if visible, and observed start/end: ____. If it cannot be identified, **stop and explain why**: ____.

For the fixture alone, after checking `asset-list.csv`, try `ip.addr == 192.0.2.10`; it retains packets in either IPv4 direction. Narrow to the chosen pair as needed, inspect packet details and nearby traffic, then **clear the display filter**. For a real case use its verified address, not this example. Record the first supporting packet’s source file and frame number: ____. Frame numbers locate packets in that particular file even under a display filter; a changed or sanitized file may need a reference map.

## 4. Three packet-evidence cards

Each card needs a real source-file frame number, displayed time **with reference/zone**, endpoints and direction, visible protocol and precise decoded field, another possible reading, and what packets cannot establish. Inspect the **visible exchange**: do not use a bare handshake as proof of application contents, process identity, approval, or intent. If the needed packets are absent or outside the file, leave the card unfilled and state that limitation.

- **A — candidate endpoints and timing.** File/frame: ____; time/reference: ____; source → destination and ports: ____; decoded field/protocol (and, if used, whether sequence numbers are `tcp.seq_raw` or relative display values): ____; alternative: ____; limit: ____.
- **B — candidate’s visible exchange.** File/frame(s): ____; time/reference: ____; direction: ____; decoded request/response or other genuinely visible protocol fields: ____; alternative: ____; limit: ____. Distinguish `frame.len`/conversation frame bytes, `tcp.len` payload bytes, and actual application-body bytes.
- **C — packet-based scheduled comparison.** File/frame(s): ____; time/reference: ____; endpoints/direction: ____; decoded scheduled-traffic field(s): ____; comparison to A/B **and note-derived expectation**: ____; alternative: ____; limit: ____. The note is context, never a packet citation.

## 5. Test both explanations, then stop

| Comparison | Observed candidate packets and frame(s) | Observed scheduled-peer packets and frame(s) | What the note claims; unresolved alternative |
| --- | --- | --- | --- |
| Timing and capture coverage | ____ | ____ | ____ |
| Peer, address mapping, and any DNS/Host labels | ____ | ____ | ____ |
| Traffic direction | ____ | ____ | ____ |
| Visible protocol and exchange | ____ | ____ | ____ |

Evidence **for and against** documented scheduled activity: ____. Evidence for and against unrelated legitimate activity: ____. Is a destination list complete, a name/peer owned as claimed, the collector clock trustworthy, and a process linked to the connection? ____.

Mark the **scheduled-activity explanation** supported only when packets *and reliable context* actually match; unsupported when a reliable comparison contradicts it; otherwise inconclusive, especially with unresolved coverage, identity, or software ownership: ____. Overall session purpose: ____; compromise finding, if any, and its separate evidential basis: ____. None of those schedule labels alone proves compromise. Request authorized process-to-connection records for the window and activity-owner confirmation of expected destinations if these would settle attribution: ____. Do not present a requested record as already observed. The unsupplied lecture case’s disposition remains **undetermined**, regardless of the synthetic result.