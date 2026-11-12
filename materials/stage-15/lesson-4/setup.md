# Setup and reproducible offline workflow

Download the complete lesson kit and extract all members into one directory. Keep `practice.pcap` unchanged. Its SHA-256 is `a9f42023bc13d94f70ef5acdbafcce71f785669d2eb5b4a0ce635bc53f475a90`: 249 filesystem bytes, two Ethernet packets. Do not substitute another DNS capture. Read the case scope before opening it.

Learners need Wireshark 4.4, with English menu labels. Windows 11 is the lesson workstation; bundled native verification images were recorded separately on actual Ubuntu 24.04 with native Wireshark 4.4.0. Optional offline rebuilding/checking uses Python 3.11 or newer, standard library only. TShark is optional for independent dissection. No live capture or administrative capture permission is necessary.

From the extracted kit directory in Windows PowerShell, these are reproducible learner commands, not claims of author-side Windows execution:

```powershell
Get-FileHash .\practice.pcap -Algorithm SHA256
Copy-Item .\practice.pcap .\working.pcap
py -3.11 .\verify_capture.py --reference .\marker.json --capture .\practice.pcap
py -3.11 .\build_capture.py --reference .\marker.json --output .\rebuilt.pcap
Get-FileHash .\rebuilt.pcap -Algorithm SHA256
& 'C:\Program Files\Wireshark\tshark.exe' -r .\practice.pcap -Y dns -T fields -e frame.number -e ip.src -e ip.dst -e dns.id -e dns.flags.response -e dns.qry.name -e dns.txt
```

Use a fresh output name for rebuilding; the builder refuses an existing path. Compare original and rebuilt hashes; a mismatch is unresolved. The raw checker validates record structure, timestamps, DNS transaction, endpoint direction, IPv4/UDP checksums, exact TXT field and strict Base64/reference equality. It rejects extra or truncated bytes. Its observed local run and TShark output are included. On Linux, replace `py -3.11` with `python3` and use `/` paths; actual executed argv is in `execution.json`.

Open `working.pcap` in Wireshark. Apply `dns`; it should display both packets. Apply `frame.number == 2`, select the response, expand Domain Name System → Answers → marker.training.example.test → TXT. Select **TXT: T0s=**, not TXT Length and not the entire packet. The four content bytes are `54 30 73 3d`; absolute zero-based frame offsets 101–104. Offset100 is the separate length byte `04`, which is excluded. Use Analyze → Show Packet Bytes (Ctrl+Shift+O). With Decode as None and Show as ASCII it displays `T0s=`. Select Decode as Base64; ASCII displays `OK`. The dialog Start0/End3 are indices within the four selected bytes, not absolute frame offsets.

Record actual field, selection, decoder and result. If the packet, selection, command or result differs, stop and record mismatch or unresolved; do not search through decoders for readable text. Close the dialog and clear the display filter to restore both packets. Display filters change visibility, not capture contents. Preserve original bytes and submit only your worksheet and authorized supporting evidence.
