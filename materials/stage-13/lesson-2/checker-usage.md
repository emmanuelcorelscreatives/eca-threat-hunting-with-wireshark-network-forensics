# Independent PCAP check: how to read the supplied evidence

The actual `check_capture.py` is a **read-only, independent classic-PCAP byte parser**; it does not import `offline-builder.py`. `independent-pcap-execution.json` records a successful execution against the packaged `practice.pcap` and `executed-fixture-spec.json`. The retained stdout is `independent-pcap-report.json`, SHA-256 `4a59333cd80160b82a95a01d6caffb0fd724320109847fa23d4439bcb3d2638c`. The executed argv names a differently located `independent-classic-pcap-checker-v2.py`; the packaged **`check_capture.py` has the same checker SHA-256** `266fadee51a03a68de535c3394b9f153797375217b624c13703217339a6f3890`. A command naming the packaged copy is a **proposed rerun**, not the original recorded argv.

## Read the report before interpreting its verdict

The report records source PCAP SHA-256 `de49b4bc93e17959c8bfad00ad38b580e358d0e8f4adb8c5c90e375b413b72a0` and spec SHA-256 `82e8296658341a7493f62baa2528231b0fcc68003ea2a844f9babc232418d20e`. Its `state: COMPLETE` and `verdict: pass` concern **this file and this specification**, not an incident, collection completeness, learner permission, endpoint process or clock accuracy. Its independent byte parsing checks **26 ordered records**, each specification timestamp, **1,982 physical file bytes**, **1,542 captured frame bytes**, included IPv4/TCP checksums, TCP flags and raw sequence/ACK observations. `decoded-fields.stdout.csv` separately shows the decoded flags, checksum-status values and retransmission indication; `all-frames.stdout.txt` supplies streams, epochs, raw TCP fields and HTTP decode but **has no flag or checksum-status columns**. `capture-info.stdout.txt` supplies file and window information. None of those decoder exports should be substituted for the independent raw-byte check.

Inspect specific report sections instead of treating `pass` as universal coverage:

| Report field | What this fixture actually shows |
| --- | --- |
| `distinctObservedSynStartFrames` | **3, 18, 19, 20, 24** are distinct observed SYN candidates across *all* tuples. Frames **18** and **19** are outside the scoped client-to-peer pair; the scoped accepted frames are **3, 20, 24** in `lessonSpecificArithmetic.acceptedScopedSynFrames`. |
| `sameTupleRawSynRetryCandidates` | Frame **4** repeats frame **3**'s directional tuple and raw SYN sequence. It is a retry candidate, not a fourth scoped connection start. The authored specification and approved native SYN view also identify that retry. |
| `rawAckContinuityChecks` | Compare each ACK with `priorObservedSequenceEnds` for the reverse tuple. **Frame 1** is `not_established_by_prior_observed_bytes`; its reverse-direction bytes were not previously captured. Other reported ACK matches do **not** erase that unresolved capture-boundary fact or prove no missing traffic. Frames **1–2** remain a midstream conversation with **no observed connection start**. Raw TCP values are not Wireshark's potentially relative sequence display. |
| `httpCapturedByteOrigins` | For scoped `GET /a`, **frame 7** has the first captured request bytes and **frame 8** completes its header; their TCP payload lengths are **17** and **25** bytes. For `GET /b`, **frame 12** both starts and completes the **42-byte** header. The first header also totals **42** bytes. These are captured byte origins, not a rule for an unseen first portion in another source. |
| `lessonSpecificArithmetic` | Scoped SYN intervals **3 → 20** and **20 → 24** are each **60,000,000 microseconds = 60.000000 seconds**. Scoped HTTP first-byte interval **7 → 12** is **20,000,000 microseconds = 20.000000 seconds**. Each series's first accepted event has no preceding accepted gap. |

The corresponding epoch subtractions from `all-frames.stdout.txt` are **1737028860.100000 − 1737028800.100000 = 60.000000 seconds**, **1737028920.100000 − 1737028860.100000 = 60.000000 seconds**, and **1737028821.100000 − 1737028801.100000 = 20.000000 seconds**. `http.request` decodes at **8** and **12**; subtracting their displayed decode-row times gives **19.980000 seconds**, a different measurement. A decoded completion frame must not replace the selected first-byte start. `independent-checker-rejection-proof.json` also records four deliberate corruptions of **new scratch copies** rejected for an IP checksum, a TCP checksum, a timestamp and truncation. This is bounded rejection evidence, not a complete security or capture-coverage proof.

## Optional read-only rerun

From the directory containing the **actual packaged files**, this proposed Linux command checks the exact checker, spec and PCAP identities first, then prints a newly calculated JSON report to **standard output**. It does not overwrite the supplied `independent-pcap-report.json` or the original PCAP. Stop if any hash check fails; do not substitute an unverified download or a renamed historic builder.

```sh
(
  set -eu
  printf '%s  %s\n' '266fadee51a03a68de535c3394b9f153797375217b624c13703217339a6f3890' 'check_capture.py' | sha256sum -c - || exit 1
  printf '%s  %s\n' '82e8296658341a7493f62baa2528231b0fcc68003ea2a844f9babc232418d20e' 'executed-fixture-spec.json' | sha256sum -c - || exit 1
  printf '%s  %s\n' 'de49b4bc93e17959c8bfad00ad38b580e358d0e8f4adb8c5c90e375b413b72a0' 'practice.pcap' | sha256sum -c - || exit 1
  python3 check_capture.py --capture practice.pcap --spec executed-fixture-spec.json
)
```

This recipe has **not** been evidenced as literally run. Read `independent-pcap-execution.json` for the actual executed argv, exit code and output hash. `builder-safety-and-rebuild-execution.json` documents the separate *current-builder* rebuild and refusal proofs. `historical-actual-execution-proof.json` is immutable **historical** command evidence, not a current checker run or complete kit inventory.

## What still requires human and source work

Use Wireshark and the worksheet to decide whether each visible packet really begins the selected kind of contact. The role-limited approved GUI evidence is indexed in `native-independent-approvals.json`: scoped SYN candidates, decoded requests and their segment origins, accepted-only epochs and displayed-row gaps have actually been shown. The older `*REF*` test marked accepted frame 3. Four additional approved `native-gap-*` views now show reference frame 10 remaining visible despite an accepted-only filter for frames 3, 20 and 24. Frame 20 then displays 58.940000 seconds from intervening response frame 10, not the true 60.000000-second accepted-start interval. Unsetting reference 10 restores rows 3, 20 and 24 and the accepted gaps. See `native-validation.md` for exact images and selected menu state; do not treat a reference response as an accepted start. A default Ethernet Endpoints tab or an unfiltered, one-second I/O graph is not proof of different tabs, filters, intervals or unseen settings; `one-second-frame-bin-arithmetic.json` is raw-record arithmetic, not GUI evidence.

For a learner-owned authorized source, record the **original capture SHA-256 and scoped peer TCP port** explicitly in the submitted worksheet narrative alongside `worksheet.csv`, as directed in `README.md` and `setup.md`. Also record capture point and directions, window and time zone, clock and loss information, scope authorization, mapping uncertainties, original frame numbers, exclusions and separate series. The checker cannot supply missing directions, earlier SYNs, unseen request bytes, an endpoint process, DNS resolution, address translation, remote instructions or permission to inspect that source. If comparable starts cannot be confirmed, report **timing unresolved**. Neither the report nor the approved PNGs are public-placement, complete-guide, Windows, main-visual or publication approval.