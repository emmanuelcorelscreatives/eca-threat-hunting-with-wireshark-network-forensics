# Offline setup and executable workflow

Use a fresh writable copy of this kit on an isolated Ubuntu 24.04 system. Install Python 3, Wireshark/TShark and LibreOffice Calc; no live capture or network request is needed. Record `tshark -v` and `libreoffice --version`. The author's recorded runs used TShark/Wireshark 4.4.0 and Calc 24.2; the lesson's production target 4.6.9 was not run. Check exact installed abbreviations with `tshark -G fields`, matching the abbreviation column exactly against `supported-fields.txt`. A substring match is insufficient.

1. Record the source filename, SHA-256, scope and actual versions in `worksheet.md`. `practice.pcap` and its byte-identical `working-copy.pcap` contain six DNS frames. The accepted supplemental Wireshark filter is `dns`; it selects six frames without renumbering them. `repeated-a.pcap` is a different two-frame source. Use the source hash for the right file.
2. Rebuild into new output names. Existing output files are refused before writing:

```sh
python3 offline-builder.py --spec dns-baseline-spec.json --output rebuilt-baseline.pcap
python3 offline-builder.py --spec repeated-a-spec.json --output rebuilt-repeated.pcap
sha256sum practice.pcap rebuilt-baseline.pcap repeated-a.pcap rebuilt-repeated.pcap
```

The baseline hashes must match each other, as must the repeated-pair hashes. The old draft spec name is reconciled to the actual consumed `dns-baseline-spec.json`; no missing PCAPNG or ODS blank worksheet is implied. `worksheet.md` is the blank provenance worksheet. `imported-repeated.ods` is a completed author import, separate from your own evidence record.

3. Generate fresh exports with the included runner. Choose a new directory; existing directories are refused. The runner checks every exact field name, records source hashes and tool version, creates a byte-identical baseline working copy, and runs the commands in the requested six-column order:

```sh
python3 run_exports.py --output-dir my-export-run
python3 verify_lab.py
```

The canonical command for baseline export is:

```sh
tshark -r working-copy.pcap -Y dns -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e dns.qry.name -e dns.a -E header=y -E separator=, -E quote=d -E occurrence=a -E aggregator=';' > timeline.csv
```

Run that literal shell example only in a fresh working directory with the authorized working copy and no existing `timeline.csv`; redirection can overwrite. The runner safely creates outputs exclusively. `-r` reads offline, `-Y` filters, `-T fields` and `-e` select columns, and redirection saves text. `-w` writes capture data and is not this export. Preserve default control-character escaping. Record the exact command and policy. For `repeated-a.pcap`, compare `occurrence=a`, `f`, and `l` in the delivered three CSV files and runner commands. First or last deliberately discards an alternative; packet importance is a different question.

4. Inspect CSV as plain text and with Python's csv reader before import. Each row must contain the six fixed columns. Baseline query frames 1, 3, 5 have empty A fields; the two-frame source has one query and frame 2 with two A answers. A semicolon separates answers within one cell, not packets or columns.
5. In Wireshark open the correct source, apply `dns`, and select a query frame and a response. Expand Frame and Domain Name System, including Questions and Answers. Compare arrival time, tuple, name and answers to the CSV; use epoch CLI output for exact characters and GUI native packet evidence for visible dissection. Record unresolved decoding/collection gaps instead of guessing. Each source has its own frame 1.
6. Open `repeated-all.csv` through Calc's Text Import. Set comma only and double quote text delimiter. Leave Merge delimiters, Evaluate formulas, Detect special numbers and Detect scientific notation off. Select all preview columns and set Column type **Text**; Format quoted field as text can also be checked. Scroll right to verify `dns.a` remains one column. Compare the preview with plain text before accepting; fix settings, never edit shifted data rows. Save your result as ODS. Confirm A2 is `1`, B2 preserves `1738573200.000000000`, F2 is blank and F3 is `198.51.100.10;198.51.100.20`. The delivered imported ODS was saved through this real UI and independently checked for string cells/no formulas. CSV quotes alone never prevent formula evaluation.
7. Repeat safe import for your baseline export and keep your worksheet with both sheets. Do not treat author screenshots or shipped controls as proof your installation executed. `import-drill.csv` is optional hypothetical import practice, never packet-derived output.
