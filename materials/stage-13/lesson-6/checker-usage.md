# Using the supplied independent PCAP checker

`check_capture.py` is a **read-only checker**, not a builder, capture tool, or authority to analyze someone else’s traffic. It parses the existing classic Ethernet PCAP bytes separately from `offline-builder.py` and compares them with the actual `executed-fixture-spec.json`. Its supported assertions are scoped to this kind of classic PCAP and its implemented IPv4/TCP and DNS-over-UDP cases; do not present it as a universal Wireshark dissector, a PCAPNG checker, or a coverage monitor.

## Identity and an optional read-only recipe

The supplied checker’s SHA-256 is `266fadee51a03a68de535c3394b9f153797375217b624c13703217339a6f3890`. To run the supplied copy from the directory containing the three files, first stop on any changed input, then let it print JSON to standard output. This recipe does **not** overwrite a capture or the retained report:

```sh
(
  printf '%s  %s\n' '266fadee51a03a68de535c3394b9f153797375217b624c13703217339a6f3890' 'check_capture.py' | sha256sum -c - || exit 1
  printf '%s  %s\n' '592d737848d6a459b2627a854af958c73003cf0179406bd234e4ce6ba4064ce3' 'executed-fixture-spec.json' | sha256sum -c - || exit 1
  printf '%s  %s\n' '38b5cf0280442fd67fe80de6f4621df2ff7a75659ae4b7579d922e9e95cd8409' 'practice.pcap' | sha256sum -c - || exit 1
  python3 check_capture.py --capture practice.pcap --spec executed-fixture-spec.json
)
```

`independent-pcap-execution.json` records an **actual** successful run whose argv names `/var/lib/trejj-studio/maintenance/wireshark-pocket-production-20261111/independent-classic-pcap-checker-v2.py`, not the copied `check_capture.py` filename in this recipe. The copied checker has the recorded checker hash. Its retained stdout is `independent-pcap-report.json` (SHA-256 `7c16cc97ea3b99792fc9b56e547e012eef3c95600ff978d5ff88051f2051c1d0`). Do not claim that the short-path student recipe was literally the recorded execution.

## Read this report, not a different lesson’s figures

For **this** `practice.pcap`, the report says `COMPLETE` and `pass` for its **implemented checks**. It records **59 frames**, **4,176 physical file bytes**, and **3,208 captured packet bytes**. It checked record count and order, timestamps and frame bytes against the actual ordered spec, raw TCP flags and sequences, payload bytes, and included IPv4 and transport checksums. `decoded-fields.stdout.csv` is a separate actual TShark export: it shows the initial SYN flags and `tcp.analysis.retransmission` value `1` on frame **13**. The checker itself calls frame 13 a **same-four-tuple, same-raw-SYN-sequence retry candidate** of frame 12; it does not manufacture a TShark analysis label.

Inspect `distinctObservedSynStartFrames`: **1, 7, 12, 19, 28, 34, 39, 45, 54**. Under the worksheet’s **A rule**—first asset-originated SYN for each distinct source-port connection to `198.51.100.20:41000`—the accepted frames are **1, 12, 19 | 28, 39, 45, 54**, and repeated frame **13** is excluded. Under the different **B data-packet rule**, the candidate frames are **10, 25 | 37, 51** in **two** reused TCP streams, whose new SYNs are **7 and 34**. `all-frames.stdout.txt` supplies the individual UTC timestamps: A’s within-authored-segment successive differences are **30, 30 | 30, 30, 30 seconds**; B’s are **60 | 60 seconds**. The **19 → 28** and **25 → 37** differences are each **420 seconds across the authored gap**, not uninterrupted intervals. The report’s `lessonSpecificArithmetic` is **empty (`{}`)**: do not import another lesson’s special arithmetic or claim this checker calculated those A/B worksheet intervals.

`rawAckContinuityChecks` classifies ACK values against previously **observed reverse-direction sequence ends**. The entries in this report match such observed ends; that is not proof that every earlier packet, collection direction, or unobserved ACK history is known. In general, an ACK not established by previously captured reverse bytes remains `not_established_by_prior_observed_bytes`, not evidence that missing packets never existed. The checker also examines captured TCP byte origins for its limited HTTP pattern; **this report’s `httpCapturedByteOrigins` is empty**. Do not infer HTTP, an application request, process identity, complete coverage, or approval from a passing check. The synthetic fixture has no demonstrated DNS, HTTP, TLS, QUIC, or UDP exercise traffic (`protocol-hierarchy.stdout.txt` and `all-frames.stdout.txt`).

`independent-checker-rejection-proof.json` records four rejected **altered scratch copies**—bad IP checksum, bad TCP checksum, changed first timestamp, and truncated last frame—while the original remained unchanged. That tests specific failure handling, not every possible error. `one-second-frame-bin-arithmetic.json` computes packet bins from raw records; it is **not** an additional GUI graph observation or a finding of collection coverage. For the actual approved native GUI states, consult `native-independent-approvals.json` and the limitations in `setup.md`.

A pass supports claims about the checked bytes of this identified synthetic file. It cannot establish the authored gap as a real outage, the traffic’s application meaning, an authorized owner, clock alignment with other records, or the correctness of an unsupplied learner capture. Complete the separate Wireshark and worksheet tasks, keep unresolved fields unresolved, and retain the required independent review before publication.