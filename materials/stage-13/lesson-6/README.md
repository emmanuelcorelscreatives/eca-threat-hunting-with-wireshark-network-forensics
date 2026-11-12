# Supplemental beacon-candidate practice — Stage 13, Lesson 6

This offline Academy kit accompanies **EMMANUEL CORELS’s** lesson, *Document a Beacon Candidate*. It does not change the lecture. The original incident capture is not supplied; `practice.pcap` is **separately labelled synthetic coursework**, not a historical case or a learner’s own collection.

A beacon is a regular check-in; a **beacon candidate** is recurring contact worth examining, not a finding of malicious purpose. Command-and-control means remote instructions to a compromised device. Timing, a SYN (the packet that starts a TCP connection), and packet counts cannot by themselves establish command-and-control, a responsible process, or authorization. The task is to define comparable events, cite their original frames and times, test ordinary explanations, provisionally rank candidates, and write a bounded brief with separate packet-observation and suspicious-interpretation confidence judgments.

## Start here

1. Read `setup.md` for source verification, the Wireshark menus, filters, and the distinction between observed packets and authored coverage. Use `DATA_DICTIONARY.md` for field and byte-unit definitions.
2. Inspect the capture and fill in `worksheet.md`: source path and SHA-256, authorization, capture point, packet window, coverage limits, time format, filter state, conversation counts, event rules, original frames, exclusions, interval subtractions, alternatives, confidence, and a targeted evidence request. Use `candidate-brief-template.md` for the ranked decision. `answer-guide.md` is the qualified synthetic-fixture key, not a case finding.
3. If checking the fixture independently, follow `checker-usage.md`. Read its actual report; a checker pass is not collection, ownership, or authorization evidence.

| Current supplied evidence | SHA-256 or identity |
|---|---|
| `practice.pcap` | `38b5cf0280442fd67fe80de6f4621df2ff7a75659ae4b7579d922e9e95cd8409`; 4,176 filesystem bytes |
| `executed-fixture-spec.json`, the actual packaged input | `592d737848d6a459b2627a854af958c73003cf0179406bd234e4ce6ba4064ce3` |
| `offline-builder.py`, the **current exclusive-creation** builder | `287db0760fd6042f4fe0ab58617ccf6df2b9bdc2f1744a1847348a776329a85c` |
| `check_capture.py`, the supplied read-only checker | `266fadee51a03a68de535c3394b9f153797375217b624c13703217339a6f3890` |
| `independent-pcap-report.json` | `7c16cc97ea3b99792fc9b56e547e012eef3c95600ff978d5ff88051f2051c1d0` |

`builder-safety-and-rebuild-execution.json` records a fresh matching rebuild with the current builder and two refusals to replace existing outputs. `historical-actual-execution-proof.json` is an **immutable earlier snapshot**: its old builder hash and older prose hashes are not the current inventory. `source-copy-provenance.json` records copied inputs *before subsequent changes*, not hashes of these finished Markdown revisions. The table is a reading guide. `current-kit-inventory.json` separately lists current delivered files, byte counts and SHA-256 values. An independent review of every resulting current guide is still required before publication.

## Separate future learner assignment

After this synthetic exercise, apply the same worksheet to an **existing capture you are authorized to analyze**, or collect one only under explicit approval for its source, interface, period, and storage. This is future learner work: no learner capture or completed learner brief is supplied. Preserve its original bytes, record its path and hash, collection point, actual collection and packet bounds separately, capture and display filters, clock and time zone, direction and missed-period limits, and any independently supported owner or schedule information. Follow the practical collection and analysis notes in `setup.md`; leave unverified fields empty. Do not generate traffic to make a pattern appear.

The supplied kit has no independently verified collection log, host process-to-connection record, software-owner approval, DNS observation, or identified application protocol. Role-limited Linux Wireshark views and packet checks are documented, but they do not constitute final-kit, Windows, main-video, visual-render, public-placement, or publication approval.