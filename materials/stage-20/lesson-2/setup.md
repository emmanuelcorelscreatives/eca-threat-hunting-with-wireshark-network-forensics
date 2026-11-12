# Setup and execution

Use preserved working copies of this extracted kit. Requirements: Windows 11 and Wireshark with TShark/capinfos on PATH; Python 3 for optional checks. Linux CLI results supplied here do not certify a Windows run. Use a terminal in the kit directory. Record tool versions and the displayed time zone. Never connect to any fixture address.

Read the Python programs before optional execution. The checker only reads files. In PowerShell, run:

```powershell
python check_capture.py delivery.pcap outbound.pcap internal.pcap
capinfos -a -e -c -I delivery.pcap
capinfos -a -e -c -I outbound.pcap
capinfos -a -e -c -I internal.pcap
tshark -r outbound.pcap -q -z conv,tcp
python -c "import csv; rows=list(csv.DictReader(open('corroborating-records.csv', newline='', encoding='utf-8'))); print(len(rows))"
```

Expected: checker pass with counts 6, 30, 5; six CSV rows. Supplied command-execution.json records the actual Linux argv and status for the included per-capture outputs. These student relative-path recipes are equivalent workflows, not a claim they were run on Windows. The checker checks record bounds, lengths, time order and IPv4/TCP checksums, not evidential truth.

Optional deterministic rebuild: choose a new directory name, then run `python offline-builder.py my-fresh-chain-build`. It refuses any existing output directory, including an empty directory. Compare the three rebuilt files with original SHA-256 values from current-kit-inventory.json using `Get-FileHash -Algorithm SHA256`. Do not replace originals. safety-tests.json records the actual initial byte-identical rebuild, an existing-output refusal, and independent truncated-file rejection.

In Windows Wireshark, use File > Open separately for each PCAP. Before filtering, open Statistics > Capture File Properties; record first/last times, packet count and available interface information. Choose View > Time Display Format > UTC Date and Time of Day if available in your version, or explicitly record your display setting. Do not infer missing interface names from this classic format. Use `ip.addr == 192.0.2.10`. Open Statistics > Conversations > TCP; record whether Limit to display filter is selected and compare endpoints, starts, durations and direction. Clear the filter to compare all packets. Capture hashes and original frame numbers do not change when filtering. Return to packet details and inspect each cited exchange; menu labels may vary by version. No supplied screenshot certifies your GUI observations.
