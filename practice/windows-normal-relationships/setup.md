# Setup and reproducible checks

Use an authorized analysis workstation with Wireshark, TShark, capinfos, Python 3 and optional PowerShell 7. Author CLI validation used Linux TShark and capinfos 4.2.2; native GUI validation used Linux Wireshark 4.4.0; exact versions and execution results are in execution.json and native-execution.json. Windows installation paths vary; in PowerShell invoke the installed executable path with `&` if it is not on PATH. Record `tshark --version`, `capinfos --version`, `python --version` and `$PSVersionTable` locally. This exercise does not install software or require network access.

Preserve synthetic-smb-relationships.pcapng, record its SHA-256, and work on a copy. On Windows use `Get-FileHash .\synthetic-smb-relationships.pcapng -Algorithm SHA256` and `Copy-Item .\synthetic-smb-relationships.pcapng .\working-copy.pcapng`. In a terminal opened in this kit directory, the offline builder command is:

```text
python build_capture.py rebuilt.pcapng
```

Use an output name that does not exist. The builder refuses replacement. It builds raw Ethernet/IPv4/TCP/SMB2 bytes using Python's standard library and writes PCAPNG; it never sends packets. The author rebuilt byte-identically and tested existing-file refusal; see execution.json. Compare the new hash with README.md. Synthetic capture scope has no real capture point or real host coverage: three designed conversations, January 16 2025, 12:01:00.000000–12:07:00.050000 UTC, 18 packets, 360.05 seconds. Six packets per conversation include a SYN/SYN-ACK/ACK, request, response and ACK; there is no FIN/RST. Gaps between conversations do not prove inactivity in a real network.

Run these commands in the kit directory. PowerShell users can paste the quoted filter unchanged. Do not substitute the invalid field `smb2.message_id`; actual TShark uses `smb2.msg_id`.

```text
capinfos -c -a -e -u synthetic-smb-relationships.pcapng
tshark -n -r synthetic-smb-relationships.pcapng -q -z conv,ip
tshark -n -r synthetic-smb-relationships.pcapng -Y "smb2 && ip.addr == 192.0.2.21" -T fields -E header=y -E separator=, -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e smb2.cmd -e smb2.flags.response -e smb2.msg_id -e smb2.tree -e smb2.nt_status
Import-Csv ./asset-inventory.csv | Select-Object asset_id,ipv4,role,expected_smb_peers,expected_shares,record_status
```

Open the working copy through File > Open, with no read filter. Choose View > Time Display Format > UTC Date and Time of Day for absolute times. Open Statistics > Conversations and the IPv4 tab. Clear “Limit to display filter” for the full capture. Record peers, directional counters, starts and duration. Close the dialog, enter `smb2` in the display filter and apply; six packets should remain. Then apply `smb2 && ip.addr == 192.0.2.21` and confirm the same six. A display filter changes visibility, not capture coverage.

Select frame 4, expand SMB2 and Tree Connect Request, and inspect the share path and Message ID. Select frame 5; expand SMB2 Header and inspect status, matching Message ID, conversation direction and Tree ID. Repeat for frames 10/11 and 16/17. Tree ID in a response identifies the synthetic tree; the share string appears in its request. Message ID 1 is reused on separate TCP streams, so match within the same conversation. The native supplement demonstrates Linux controls; use your installed Windows menu equivalents and record your own observations. No learner-own-capture task is claimed completed by the author.

In a real authorized investigation first document capture point, address ownership at that time, visibility and clock quality. A switched access port may miss other hosts. When data is missing, stop and seek authorized host/service, identity, process, file activity and approved change records. Never capture production traffic without authorization.
