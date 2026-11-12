# Supplemental decision-log practice

This separate Academy synthetic exercise supports the saved lesson. The unavailable lecture case remains unavailable: these files provide no findings, peers, frames or ranking for it. All addresses are documentation-only. Open files offline; do not contact them or start a live capture.

Keep every file in the downloaded kit together. Open normal-day.pcap and practice.pcap in Wireshark. The former spans 2025-02-03 15:00–21:00 UTC; the latter spans 2025-02-04 20:15–20:45 UTC. practice.pcap is the incident slice; the draft name incident.pcap is superseded. Use worksheet.md and a working copy of decision-log-template.csv. context.json contains the inventory, dated jobs, device configuration and missing-telemetry records. DATA_DICTIONARY.md describes their interpretation. These are synthetic context, never packet-derived identity.

Both captures are supplied. Optional offline reproduction with Python 3 standard library, from this directory:

```sh
python3 offline-builder.py --spec normal-day.json --output normal-day-rebuilt.pcap
python3 offline-builder.py --spec incident-spec.json --output incident-rebuilt.pcap
python3 verify-case.py
```

The builder sends no packets and refuses an existing output. Choose fresh output names rather than overwriting evidence. The checker reads the supplied canonical names and context without modifying them. It checks checksums, sequence/acknowledgment progression, exact authored events, times and synthetic record joins. Author execution retained in current-execution-receipt.json includes two fresh byte-identical rebuilds and two overwrite refusals. verified-two-capture-results.json contains actual read-only checker results. The *.stdout.txt and *.stderr.txt files retain real native TShark 4.4.0 decoding. Old assembly-manifest.json and unsuffixed all-frames/statistics logs document the earlier incident-only assembly; current two-file results supersede their incomplete inventory.

Use View → Time Display Format to select UTC date/time in your installation and verify the date. Compare the 20:15–20:45 clock window on each date; not all six hours against 30 minutes. Capture point and coverage are modeled, not measured: authored event lists are complete only for this tiny fixture. Neither file claims complete environmental traffic. Packet bytes include headers and retransmissions if present; they are not unique transferred content.

The current local kit is pending independent approval and subsequent Academy repository publication. No new public URL or commit is asserted here. Proposed earlier practice/decision-log scripts/CSV paths are reconciled to the actual flat kit: offline-builder.py, verify-case.py, two JSON specs and context.json. All original inventory/job/device/coverage information remains in context.json; no external CSV is required.
