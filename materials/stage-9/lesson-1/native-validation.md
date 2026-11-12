# Native DNS validation and current provenance

Actual native Linux Wireshark 4.4.0 ran on Ubuntu 24.04 in isolated sessions without changing either packet file. The builder-generated `practice.pcap` and the separate author-collected `academy-loopback-dns.pcap` each have four frames and 428 physical bytes, but have different hashes, tuples, times and pairing. Equal byte counts do not make them the same capture. No Windows execution, historical incident or learner-owned capture is claimed.

## Original synthetic fixture

`native-independent-approvals.json` binds each delivered image to its exact SHA-256 and immutable independent review receipt. Original views establish File Open without a read filter, the opened full packet list, Properties, the checked UTC menu and applied timestamps, the accepted `dns` filter, and filter clearing.

The additional `native-original-details-frame-1-dns-details.png` through `native-original-details-frame-4-dns-details.png` show expanded DNS Questions, Answers and response/request links for pairs 1 ↔ 4 and 2 ↔ 3. The other two `native-original-details-*` views show the accepted DNS filter and restored full four-frame view. These approvals are separate from the original all-frames CLI log and from builder predictions.

`dns-details.execution.json` records the actual new verbose read of the original unchanged capture using `tshark -n -r practice.pcap -Y dns -V`. The output verifies UDP ports, IDs, query flags 0x0100, response flags 0x8180, A/IN Questions, and the Answer owner, type, class, TTL and address. The receipt records the original absolute argv; the shorter command here names the same options for explanation.

`decoded-fields.execution.json` binds the separate checksum-enabled CSV. That output links frame 3 to query frame 2, and frame 4 to query frame 1. Single-pass query-side response-in fields remain blank. Full-file GUI linking was verified separately; missing CSV values have not been filled from the design.

The checksum-enabled CSV records IPv4 and UDP status 1, Good, in every original frame. The pinned Wireshark 4.4.0 source enum `proto_checksum_enum_e` in `epan/proto.h` defines Bad as 0, Good as 1, Unverified as 2, Not Present as 3 and Illegal as 4. The default verbose and GUI views remain Unverified because they did not enable those preferences. An empty malformed selection is not a checksum test or a proof of coverage.

`native-file-accounting.json` describes the original capture's three distinct measurements: 428 physical bytes, 340 packet bytes and a recorded Properties counter of 412 bytes. The classic-PCAP reader-counter explanation applies to this recorded Linux 4.4 build and format; it is not a replacement for filesystem size or a claim about untested formats.

## Separate actual Academy collection

The six `native-academy-*` views have independent approvals against the actual local collection hash. They show the accepted DNS filter, expanded original frames 1–4 with pairs 1 ↔ 2 and 3 ↔ 4, and the restored full view. They do not use the first capture's hashes, link model or pair assignments.

`academy-collection-notes.md` and the application receipts record the controlled loopback collection point, observation window, actual requests and replies, and coverage limits. The loopback server is not an upstream resolver, a user identity or a historical endpoint. That capture has its own checksum-enabled CSV. Its results are not inferred from the first capture.

These checks demonstrate course methods. The learner's own-capture exercise remains unperformed until the learner supplies authorized evidence and real collection notes.

## Preserved history and current integrity

`historical-actual-execution-proof.json` is the unchanged original manifest, including its old prose hashes, pending state and erroneous empty CSV headers. `source-copy-provenance.json` records its rename. `current-csv-header-verification.json` supplies the actual new read-only parse of the unchanged header-only worksheet: 33 columns and no data rows. It corrects the old claim without rewriting history.

The current inventory binds this delivery. `builder-safety-and-rebuild-execution.json` records the exclusive-output builder's fresh byte-identical rebuild and two no-overwrite tests. The two JSON specifications deliberately remain byte-distinct historical variants; only `executed-fixture-spec.json` is the attested input. Setup now gives that file's complete 64-character hexadecimal hash, correcting a truncated display without changing the file.

`setup-recipe-verification.json` records actual execution of the documented setup recipe with approved inputs. It also records four dedicated scratch cases: a missing first file, a modified builder, a modified specification and a modified PCAP. All four were rejected before builder execution; approved source files remained unchanged. Only the KIT placeholder and the tool PATH were supplied for those runs. The student recipe checks approved source hashes before executing the builder, creates a fresh temporary output, verifies its hash and compares its bytes.
