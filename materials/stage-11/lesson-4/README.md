# Investigate name-resolution anomalies

This is a complete, separate synthetic Academy lab for Stage 11 Lesson 4. It supplements the saved lecture's deliberate no-capture demonstration; it is not the missing historical case, a real network collection, or homework already completed by a learner. The lecture and instructor remain unchanged.

Start with setup.md, complete worksheet.md, then compare answer-guide.md. All files use paths relative to this folder. practice.pcap contains 17 constructed Ethernet/IPv4 packets spanning 2025-02-03 12:00:00.000000–12:00:03.200000 UTC: LLMNR, NBNS broadcast and configured-server exchanges, DNS, and a later payload-free TCP connection. The asset map is an explicit scenario assumption, not confirmed real ownership. The client subnet is assumed to be 192.0.2.0/24.

The old draft's DNS-only fixture and proposed filenames are superseded by this complete fixture-spec.json and build.py. One canonical practice.pcap serves the old proposed practice/supplemental-resolution filenames; there is no second distinct capture to locate. paper-examples.csv remains a separate hypothetical comparison table with no packet frame references.

Execution evidence records actual Ubuntu 24.04 / native TShark 4.4.0 checks, deterministic rebuild and refusal to overwrite an existing file. Native screenshots show the actual full list, applied filters and restored list. These are limited demonstrations; run the packet-details exercise yourself. No Windows execution is claimed. Native screenshots are authentic application captures, not generated UI.
