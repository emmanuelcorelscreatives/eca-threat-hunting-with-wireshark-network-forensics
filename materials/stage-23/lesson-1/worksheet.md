# Choose the Durable Behaviour to Monitor — worksheet

**Threat Hunting with Wireshark Course, Stage 23, Lesson 1. Instructor: EMMANUEL CORELS.**

Use the separately labelled **synthetic Academy** `practice.pcap` to practise choosing a behaviour that remains worth reviewing when a destination changes. It is **not** the unavailable narrated incident, a production capture, or evidence of malicious activity. The original case and its packet references were not supplied. Inspect only captures you are authorized to use. A future investigation requires your **own authorized capture and context**; do not transfer this exercise’s observations to it. Keep observation, interpretation and unknowns separate. Write `not supplied` rather than inventing a source.

## Evidence boundary and collection record

From the kit directory, `sha256sum -- practice.pcap` is a read-only way to check your working copy. Compare the result with the expected SHA-256, `a73bab65f48cc475e2d638181aa8596ba662af89eb2e86c165b3df95d1905e7a` (`capture-info.stdout.txt`; `independent-pcap-report.json`). Stop if it differs. Do not rebuild or overwrite the supplied capture for this worksheet.

The current `offline-builder.py` creates outputs exclusively. `builder-safety-and-rebuild-execution.json` records an actual fresh, matching rebuild and refusals to replace both identical and different existing outputs. The immutable `historical-actual-execution-proof.json` instead preserves the original execution arguments, older builder hash and older prose hashes. It is **not a current-file inventory**. `source-copy-provenance.json` also records files before later changes, not the final worksheet. The supplied current evidence inventory identifies the supplied files; after documentation changes, a refreshed final-file inventory is still required. Do not alter historical records to make their hashes appear current.

Historical versions of setup.md, answer-guide.md and DATA_DICTIONARY.md contained then-pending overwrite or GUI-check statements. Those statements describe earlier snapshots, not the linked current guides or this final inventory. Use the specific later evidence for those checks without claiming every remaining task is complete. `independent-pcap-execution.json` records the checker invocation under its original private filename; the same checker bytes are supplied as `check_capture.py`. Neither that execution nor the historical logs prove a suggested student recipe ran literally. No code was executed to produce this worksheet.

Complete these fields for **each** capture you analyse. Start a separate record for any later learner-owned capture.

| Collection and identity field | Your record and source |
| --- | --- |
| Capture filename, working-copy path and SHA-256 |  |
| Who authorized inspection; permitted assets, purpose and handling limits |  |
| Capture provider, collection point and interface; which directions and segments are evidenced |  |
| Capture or read filters, packet loss or collection gaps, clock and time-zone information |  |
| First and last **recorded packet** times in UTC; requested review window |  |
| Inventory version, asset owners and relevant packet frame numbers |  |
| Original-investigation references, if independently supplied | Write `original case unavailable` for this kit. |
| Unknown coverage, ownership or completeness; source needed to resolve each |  |

`asset-inventory.csv` assigns `LAB-WS-01` (`192.0.2.10`) and `LAB-WS-02` (`192.0.2.11`) to `review-lab-workstations`. `LAB-RESOLVER-01` (`192.0.2.53`) belongs to `lab-infrastructure`; external peers are not inventory members. These are **authored roles**, not discovered processes or confirmed owners. `executed-fixture-spec.json` describes a synthetic lab-segment link, not measured sensor coverage. `fixture-spec.json` is a byte-identical spec alias, not independent corroboration.

`capture-info.stdout.txt` reports one Ethernet interface, 32 packets and a **240.260000-second first-to-last-packet span**. Use its times with the explicit UTC fields for frames 1 and 32 in `all-frames.stdout.txt`. Neither file establishes continuous collection or visibility outside the recorded packets. Which coverage and ownership fields above remain `not supplied`?

## 1. Inspect conversations, time and underlying packets

Use the course target: **Wireshark 4.4 on Ubuntu 24.04 LTS**, in English with a light theme. Record your actual application and OS versions. The approved native images show Wireshark 4.4.0; `native-host-platform-v6.json` separately records the actual Ubuntu 24.04.5 LTS host.

1. Open your authorized working copy using **File → Open** and leave **Read filter** blank. Clear the display-filter bar before inspecting surrounding traffic.
2. Choose **View → Time Display Format → UTC Date and Time of Day**. Verify the **radio dot**, not a highlighted menu row. Absolute UTC packet times are distinct from relative conversation starts and graph times.
3. Choose **Statistics → Conversations**, select **TCP**, and check whether **Limit to display filter** is off. Record endpoint IP addresses and **both ports**, directional packet and frame-byte counts, relative start and observed duration.
4. Close the dialog. Use **Go → Go to Packet**, enter a required frame number, and select it. In Packet Details, expand **Internet Protocol Version 4** and **Transmission Control Protocol**, including **Flags**. Inspect source, destination, ports, flags, sequence and acknowledgment values in both directions. Repeat for each handshake and its follow-up packets.
5. Enter `tcp.flags.syn == 1 && tcp.flags.ack == 0` in the display-filter bar and press **Enter**. Record the displayed frames. Clear the expression and press **Enter** to restore surrounding DNS, handshake and teardown packets. A filter match is not automatically a distinct start.

Wireshark may display relative TCP sequence numbers. Use `tcp.seq_raw` and `tcp.ack_raw` in `all-frames.stdout.txt` or `decoded-fields.stdout.csv` for on-wire numbers; do not copy a relative GUI value into a raw-sequence field. `frame.time_utc` in the earlier export is human-readable UTC, not ISO 8601; `frame.time_epoch` is decimal epoch seconds.

### What the saved native evidence actually establishes

The exact role-limited approvals are recorded in `native-independent-approvals.json`:

- `native-00-file-open.png`: blank read filter.
- `native-01-unfiltered.png`: empty display filter and 32 packets.
- `native-04-conversations-tcp.png`: **TCP · 4** selected, with **Limit to display filter** unchecked; four seven-packet conversations, each with 378 frame bytes and a 0.1600-second observed duration.
- `native-05-endpoints.png`: the default **Ethernet · 7** Endpoints tab, **not IPv4 Endpoints**. If you select IPv4 yourself, record that as your own observation.
- `native-utc-menu.png`: the actual UTC Date and Time of Day radio selection. `native-utc-applied.png`: the applied, **unfiltered** UTC packet list, not a SYN-filtered timestamp view.
- `native-10-filter-01.png`: the applied SYN-only expression and exactly frames **3, 10, 19 and 26**. `native-99-filter-cleared.png`: the full packet list restored.

New exact-pass packet views document all four handshakes and their closures, plus surrounding DNS. Graph-to-packet actions at 60 and 120 seconds are recorded in `native-validation.md`. Record your own actions separately; image approval does not approve hidden settings, the whole kit, lecture visuals or publication.

Record **one row per proposed distinct connection**, including the scoped peer port. The starting references are prompts, not substitutes for inspection.

| First frame | Inventory asset and source IP:port | Peer IP:port and direction | First-frame UTC or epoch | Conversation relative start; observed duration | Asset → peer and peer → asset packets/frame bytes | SYN, SYN/ACK, ACK frame and flag checks; interpretation |
| --- | --- | --- | --- | --- | --- | --- |
| 3 |  |  |  |  |  |  |
| 10 |  |  |  |  |  |  |
| 19 |  |  |  |  |  |  |
| 26 |  |  |  |  |  |  |

**Checkable event rule:** an observed initiating TCP SYN has SYN = 1 and ACK = 0, an inventory-group source IP and source port, a scoped peer IP and destination port, and a packet timestamp. Confirm the reverse-direction SYN/ACK and asset ACK on the same four-tuple before describing a completed **observed handshake**. A lone SYN supports an **observed attempt**, not a completed connection. Do not count a same-direction, same-four-tuple, same-raw-sequence SYN retry as another distinct start. A new destination or source port may distinguish observed four-tuples, but inspect the packets rather than counting graph peaks, ACKs or closures as starts. This fixture’s observed peer port is **8443**; the proposed peer-independent behaviour must not depend on a particular destination address or an unexamined port assumption.

For comparison, the actual independent TShark export `decoded-fields.stdout.csv`, recorded by `decoded-fields.execution.json`, decodes SYN-only `0x0002` at frames **3, 10, 19 and 26**, reverse SYN/ACK `0x0012` at **4, 11, 20 and 27**, and asset ACK `0x0010` at **5, 12, 21 and 28**. The earlier all-frame export did not contain TCP flags. The saved stderr warning describes a historical root execution; it is not advice to run Wireshark as root.

`independent-pcap-report.json` was produced by a separate raw-byte parser without importing the builder. It validates the included frame count, order, times, checksums, flags and raw sequence values against the actual spec, and examines ACK coverage, retry candidates and captured HTTP byte origins. Its distinct observed SYN starts are `[3, 10, 19, 26]`, its same-tuple raw SYN retry-candidate list is empty, and its listed ACKs match earlier **observed** reverse-sequence ends. This does **not** prove complete capture, authorization, clock accuracy or knowledge of traffic outside this file. Unknown prior ACK coverage beyond those within-file matches remains unresolved. The empty `malformed.stdout.txt` selection is not a checksum or coverage test.

Record raw sequence and ACK evidence for each handshake: ________

Record your packet-detail observations, application/OS versions and any uncompleted GUI steps: ________

## 2. Use I/O Graphs to choose windows, not sessions

Choose **Statistics → I/O Graphs**. Record each enabled row’s full display filter, interval, x-axis reference and y-axis unit **before** interpreting peaks. Widen the Display Filter column if necessary. Note a candidate window, return to the packet list, and use **Go → Go to Packet** to inspect its underlying frames and four-tuples. Clear any temporary display filter to inspect surrounding traffic. A display filter narrows a working view; it is neither an operational alert nor a way to recover uncollected packets.

The approved `native-graph-full-filter-column.png` shows **All Packets** with a blank filter and a separately enabled **TCP Errors** row with `tcp.analysis.flags`. Its interval is **1 sec**, **Time of day** is unchecked, its x-axis is relative **Time (s)**, and its y-axis is **Packets/1 sec**. The All Packets peaks are **9, 7, 9 and 7**, near relative seconds **0, 60, 120 and 240**. Do not claim a SYN-filtered graph, another interval, a time-of-day graph or hidden settings from this view.

`one-second-frame-bin-arithmetic.json` assigns frames **1–9**, **10–16**, **17–25** and **26–32** to those one-second bins using raw-record timestamps. It is **raw-record arithmetic, not another GUI observation**. DNS packets contribute to the first and third All Packets peaks. A peak need not mark a new connection; a quiet stretch need not mean no outside activity.

| Graph row and its visible filter | Interval, time reference and unit | Window selected; packet frames checked | What the packets show | What the graph or collection cannot establish |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |
|  |  |  |  |  |

Which inventory member has three distinct observed starts to changing peers, and which has only one? Calculate the intervals between the first member’s **first SYN timestamps** using `all-frames.stdout.txt` or `decoded-fields.stdout.csv`. Show the timestamps, subtraction and units: ________

Explain why the short-window spacing does **not** establish a longer operating cycle or recurrence for every group member: ________

The supplied author walkthrough now records packet-specific GUI details and graph-to-packet actions at 60 and 120 seconds. Follow `native-validation.md`, then record your own observations for the assigned source. The 240-second count is supported, but no successful 240-second graph-click action is claimed.

## 3. Match names, packets and byte meanings

Record the two **captured DNS** query/response pairs using frames **1–2** and **17–18** in `all-frames.stdout.txt`, `decoded-fields.stdout.csv` and `independent-pcap-report.json`. Include client, resolver, queried name, A answer, UTC times and a separately evidenced later TCP peer and first frame.

| DNS query / answer frames | Client → resolver; queried name | Recorded answer and UTC times | Later matching TCP peer and frame | Unsupported inference or missing source |
| --- | --- | --- | --- | --- |
| 1 / 2 |  |  |  |  |
| 17 / 18 |  |  |  |  |

Identify TCP peers for which **this capture** contains no lookup: ________

Does a preceding answer prove an application used it? Does an absent captured query prove no lookup occurred elsewhere? Explain each limit: ________

Distinguish the following quantities:

- **2,400 physical PCAP file bytes** (`capture-info.stdout.txt`; `independent-pcap-report.json`).
- **1,864 captured frame bytes**: DNS contributes 4 frames / 352 frame bytes; TCP contributes 28 frames / 1,512 frame bytes (`protocol-hierarchy.stdout.txt`).
- Each TCP conversation’s **7 frames / 378 frame bytes**, comprising asset → peer **4 frames / 216 frame bytes** and peer → asset **3 frames / 162 frame bytes** (`tcp-conversations.stdout.txt`). These are not application-byte counts.
- TCP **application bytes**: every TCP `tcp.len` is zero in `all-frames.stdout.txt` and `decoded-fields.stdout.csv`; payload fields are empty. `independent-pcap-report.json` has no captured HTTP byte origins.

The approved `native-03-properties.png` visibly shows a native **Length of 2,384 bytes**, while the physical file is **2,400 bytes**. `native-file-accounting.json` reconciles the actual file as **24 global-header bytes + 32 × 16 record-header bytes + 1,864 captured bytes = 2,400**. Do not infer truncation from that native counter difference.

Record what the protocol hierarchy and available HTTP and payload fields actually show, and whether any supplied source establishes TLS: ________

Port **8443** and a TCP handshake do not establish TLS, HTTP, decrypted content, an application’s purpose or an initiating process. Name the appropriate authorized capture, endpoint records or authorized secrets needed for each richer claim; do not manufacture an application exchange: ________

## 4. Separate an indicator from a durable candidate

Write **(a)** one peer-specific address or captured domain useful for revisiting an observed event, with its packet reference, and **(b)** a **question**, not a malicious-activity verdict, about recurring **outbound distinct connection starts** by an inventory-defined group during a defined, adequately covered review window. State the initiating asset role and direction, accepted-event rule, intended source fields, review period and amount of repetition that would merit contextual review. Do not silently use the fixture’s short span as a production monitoring window.

- Observed indicator, capture SHA-256, frame and UTC: ________
- Packet-supported starting observation, with frames: ________
- Candidate **question** and inventory group: ________
- Proposed distinct-start and retry rule, source and peer **ports**, direction, review window and telemetry: ________
- Repetition threshold for contextual review and its justification: ________
- Would the question still matter if the peer address changed? ________
- Which group members show recurrence **in this file**, and which do not? ________
- Interpretation, alternatives and unknowns, separate from packet facts: ________

Do not label regular outbound communication generally suspicious. Preserve any original investigation’s packet references with that investigation; none is available here. Test a proposed detection against telemetry across the intended group and window rather than asserting it from a display filter.

## 5. Test every claim against a source

Fill the table with `observed`, `inferred`, `not supplied` or `unsupported`. Cite the actual field and frame or record, and request the missing source. The fixture’s DNS packets are **not independent DNS logs**; a lookup alone is **not** evidence of a later connection. Packet headers can show recorded peers, ports, direction, protocol and timestamps; they cannot identify an initiating process or intent.

| Claim | Observed / inferred / not supplied / unsupported | Source and frame or field | Missing requirement or limit |
| --- | --- | --- | --- |
| Timestamped, distinct initiating starts and retry treatment |  |  |  |
| Endpoints, source and peer ports, protocol, direction and volume |  |  |  |
| Recorded name lookup and answer |  |  |  |
| **Later**, separately evidenced network connection |  |  |  |
| Behaviour across the whole inventory group and desired window |  |  |  |
| Initiating application or process |  |  |  |
| Visible HTTP or other application content; encrypted content |  |  |  |
| Capture-point coverage, ownership and authorization |  |  |  |

For broader start or volume claims, specify the required **packet, connection or network-flow records**, collection point, time coverage and fields for endpoints, both ports, protocol, timestamps, direction and needed volume. Flows may omit full payload, process identity and application content.

For name-lookup claims, request **DNS logs** identifying relevant client or resolver activity with query, answer and time fields. Separately obtain network evidence that a later connection occurred; the lookup cannot prove it.

For software attribution, request **endpoint connection records linking a process to its connection**. Do not join a process to a packet on timing alone. Protected message content requires an appropriate authorized capture and suitable authorized decryption material. If a source or field is absent, narrow or hold the claim.

## 6. Test coverage, alternative causes and next action

Was both-direction traffic captured at the necessary observation point throughout the **intended** window, with surrounding unfiltered traffic preserved? Which segments could be missed? Could a short window, collection gap, longer cycle, address translation or shared service alter the interpretation or obscure the asset?

A no-match result means only that the named source did not show the behaviour **under its collection conditions**. Compare asset roles and obtained owner records with possible approved monitoring, updates, backups or maintenance schedules. These remain **alternatives**, not confirmed explanations without ownership and authorization evidence. A server’s scheduled activity may be normal; an incomplete capture cannot show events outside its window.

- Specific blind spot and its effect on confidence: ________
- Specific observation point, owner, network-flow, DNS or endpoint record to request: ________
- Candidate narrowed or held pending which evidence, and why: ________
- Packet-supported observation to carry forward: ________
- Visibility limit and unanswered original-investigation questions to carry into **Write a Reusable Hunt Playbook**: ________

Before choosing the candidate, answer both: **Would it remain worth reviewing if the peer address changed? Can the named telemetry show it across the intended group and window?** If either answer is uncertain, narrow the claim or request the specific missing evidence.

### Future learner-owned investigation — not completed by this kit

Before collecting or opening another capture, arrange permission for the assets, collection point, purpose, window, storage and access. Ask the authorized owner which interface or observation point can see the required traffic and both directions. Agree any capture filter and collection duration before collection; use your organization’s approved collection procedure and retention limits rather than generating traffic or capturing an unrelated segment.

Record collector/provider, approval reference, interface, observation point, requested and actual collection start/end times, clock/time zone, capture filters, snap length, reported drops or gaps, and relevant inventory/owner sources. Preserve an untouched original where permitted and inspect an authorized working copy. Record its filename and SHA-256 in a **new collection record above**; confirm first and last recorded packet times and whether the available window and point can support the intended question. Unknown collection notes remain unknown.

Repeat the native menus, graph-window review and packet-detail checks on **that capture**, recording its own frame numbers, source and scoped peer ports, DNS observations and uncertainties. Obtain authorized flow, DNS and endpoint records only for claims they can support. Do not substitute this synthetic file, its independently checked bytes or a screenshot for a completed learner investigation.

### Submission and validation status

Submit your collection record, conversation and flag checks, graph-window table, interval calculation, DNS table, byte interpretation, candidate question, source-matching table, coverage assessment and specific next-evidence requests. Clearly separate your own observations from saved fixture checks and future work.

The missing original case, real ownership/authorization context, real collection coverage and any required independent flow, DNS or endpoint records remain unresolved. The recorded native walkthrough and final inventory are supplied; separate complete independent review remains required. Refresh the inventory after any later file changes. This worksheet claims no public placement, publication, main visual or render approval and does not change the lecture narration.
