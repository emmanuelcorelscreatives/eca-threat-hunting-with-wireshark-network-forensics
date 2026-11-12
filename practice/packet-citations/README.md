# Make packet citations reproducible

This complete supplemental offline exercise contains deliberately synthetic TCP and DNS packets. It is separate from the unavailable narrated case and from your own authorized capture. Leave the real-case worksheet fields blank until you have that identified original. No network access, credentials, packet transmission or pip package is required.

Download all files together. Requirements: Python 3 and Wireshark tools (TShark, Editcap, Mergecap), plus Wireshark GUI. Put command-line tools on PATH, or set WIRESHARK_BIN_DIR to their directory. The maintainer executed the scripts on Ubuntu 24.04.5 LTS with TShark/Editcap 4.4.0 and the Mergecap version recorded in actual-verification.json. Native GUI evidence is Linux, not Windows validation.

From this directory:

```sh
python3 verify_fixtures.py
python3 build_fixtures.py --output ../citation-rebuild
python3 verify_fixtures.py --directory ../citation-rebuild
```

Choose a NEW output directory for each rebuild. The build refuses an existing directory; offline-builder.py refuses an existing output file. Retain originals. This maintained recipe replaces the prior draft's fixtures/practice.pcap copy command, fixtures/ and outputs/ prefixes, unimplemented verification programs and repository-root command paths. All delivered captures are in this directory. original-a.pcap is the six-frame A capture previously called practice.pcap; b-dns.pcap and a4-copy.pcap are intermediate files, original-b.pcap is their time-ordered assembly. reference-displayed-a.pcap is an Editcap subset, never a claimed GUI export. merged-time.pcapng merges A and B; equal-time duplicate ordering is observed per exact file, never assumed portable.

Open original-a.pcap in Wireshark. Confirm its name and SHA-256 with Statistics → Capture File Properties against checked-intake.json; stop on mismatch. Set View → Time Display Format to UTC Date and Time of Day and record the reviewing computer's time zone. Apply tcp.len > 0. Record original No. 4 and 5, not filtered row positions 1 and 2. Clear the filter and use Go → Go to Packet for frame 4. Check neighboring packets and Analyze → Follow → TCP Stream, then return to the original. Do not substitute a stream index from another file.

Apply tcp.len > 0 again. Use File → Export Specified Packets, choose Displayed packets and All packets in that displayed range, and save a NEW student-displayed-a.pcapng outside the originals. Record the actual options and hash. Verify your actual export:

```sh
python3 verify_fixtures.py --export ../student-displayed-a.pcapng
```

The two packet records must match A4/A5 in timestamp and full captured bytes. Your PCAPNG whole-file hash may differ because export/container metadata differ. Do not copy the maintainer's export hash as your own.

Complete all five worksheet tasks, compare checked answers, and have another reviewer reproduce the exact file/hash/frame citation. Match all derivative records by bytes and time; the duplicate A4/B2 source attribution remains ambiguous from those records alone. Hashes identify saved bytes, not collection authority, user identity, capture coverage, clock accuracy or malicious intent.
