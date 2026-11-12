# Checked DNS transaction key and evidence limits

This key concerns the original synthetic `practice.pcap`, SHA-256 `040d42163acaf27081d99a6928d8362f5e7d4ca4a949d3e77522e5742c4e19c6`. It is separate from the additional author-collected `academy-loopback-dns.pcap` and from a learner's own capture. Keep their frame numbers, hashes and conclusions separate.

The original CLI logs remain unchanged. The newer `decoded-fields.stdout.csv` and its execution receipt provide independent field dissection with checksum verification enabled. `dns-details.stdout.txt` and its receipt provide a separate actual verbose DNS read. Expanded native DNS views have exact independent approvals in `native-independent-approvals.json`. Newly checked fields must not be attributed to the older all-frames export. These are practice results, not a historical incident finding.

## File and observed transactions

The original capture contains four Ethernet/IPv4/UDP/DNS frames with microsecond timestamp precision. It has 428 physical file bytes and 340 captured frame bytes. Its window is 2025-02-11 14:00:00.000000 through 14:00:00.055000 UTC. The readable `frame.time_utc` output is not ISO 8601; padded fractional digits do not increase capture precision. Frames 1 and 2 are 77 bytes each, and frames 3 and 4 are 93 bytes each.

| Query → reply frames | UTC query → reply times | Observed query tuple and reverse reply | Transaction ID and Question |
| --- | --- | --- | --- |
| 1 → 4 | 14:00:00.000000 → 14:00:00.055000 | Query: 192.0.2.10:53001 → 192.0.2.53:53. Reply: 192.0.2.53:53 → 192.0.2.10:53001. | ID 0x2201 (decimal 8705); docs.academy.test; type A (1); class IN (1). |
| 2 → 3 | 14:00:00.025000 → 14:00:00.045000 | Query: 192.0.2.53:54100 → 198.51.100.53:53. Reply: 198.51.100.53:53 → 192.0.2.53:54100. | ID 0x3301 (decimal 13057); docs.academy.test; type A (1); class IN (1). |

Actual verbose dissection shows query flags 0x0100 and response flags 0x8180. Both replies have the response bit set and response code 0 (NOERROR). Each repeats the Question docs.academy.test, type A, class IN. Each **Answers** section contains one record: owner docs.academy.test, type A, class IN, TTL 60 seconds, address 203.0.113.42. A repeated Question is not automatically an Answer owner; here the Answer owner was checked separately.

The expanded native Question and Answers views corroborate those fields and show links between frames 1 and 4, and between frames 2 and 3. The newer single-pass CSV records `dns.response_to=2` on frame 3 and `dns.response_to=1` on frame 4. Its query-side `dns.response_in` cells are blank because the replies had not yet been processed in that pass. Do not fill those actual blank cells with expected values. Full-file GUI linking is separate evidence. Pairing also agrees with the full reverse tuples, matching IDs, matching Questions and measured times; an ID alone is insufficient.

The default verbose DNS read reports checksums as Unverified. The separate decoded-fields execution explicitly enabled IPv4 and UDP checksum checks and recorded status 1 for both protocols in every original frame. The pinned source enum defines 1 as Good. This is a distinct observation, not a result inferred from the malformed filter or retroactively attributed to the default verbose or GUI view.

There is no TCP conversation, HTTP payload, transferred application file or subsequent connection to the returned address in this capture. An empty `_ws.malformed` selection establishes neither checksum correctness nor complete capture coverage. Frame bytes include protocol headers; neither 340 packet bytes nor 428 PCAP bytes measures an application file.

## Requester, forwarding and cache limits

`collection-notes.md` supplies an **authored link model**, not independently measured sensor placement. In that model, 192.0.2.10 is the client-facing requester and 192.0.2.53 is the requester visible upstream. A classic-PCAP logical interface does not prove either physical link. The upstream pair alone does not identify 192.0.2.10, a user or an application.

The shared Question and close timing are consistent with the modeled forwarding relationship. They do not establish that this particular client caused this particular upstream request. Contemporaneous client-facing packets and resolver client-request or forwarding records would be needed for stronger attribution.

This file shows an upstream pair and does not demonstrate a cache hit. In another capture, a client reply without visible upstream traffic could reflect cached resolution or missing upstream coverage. Test both explanations against capture placement, both directions, resolver or cache records, and a contemporaneous upstream view. An empty filter proves neither explanation.

A returned address is a resolution lead, not proof of a later connection or real ownership. A name displayed beside an IP may come from Wireshark name resolution; use the reply's inspected Answers section when reporting a returned record.

The original four-frame practice contains no AAAA, CNAME, negative or empty Answer, incomplete pair, or repeated-lookup/cache case. Exercise 7 asks how these would be recorded **if present** in another authorized capture. An AAAA value is an IPv6 address, a CNAME is an alias, and NOERROR alone does not guarantee a usable address. Do not invent additional frames to illustrate absent behavior.

## Additional actual Academy example and learner task

`academy-collection-notes.md` and `academy-collection.json` document a separate real local UDP socket exchange captured on the author's owned loopback interface. Its two pairs are 1 → 2 and 3 → 4. They are not the original fixture's pairs 1 → 4 and 2 → 3. Use the additional example's own hash, addresses, times and answer key.

That example demonstrates actual authorized collection, notes and native DNS inspection. It does not impersonate a learner's own capture, an external resolver or a historical incident. It has no forwarded upstream leg and provides no evidence of cache behavior or an external user or process.

For the lecture's own-capture exercise, the learner must obtain an authorized offline capture and its actual collection notes, apply `dns`, match the full transaction and transcribe section-level Answers. Grade their method and honest limits, not agreement with either supplied sample. An incomplete transaction or upstream-only view remains unresolved, with the next required evidence stated. The supplied blank 33-column worksheet supports this task; no learner execution is claimed in advance.
