# Supplemental internal fan-out and sequencing lab

This runnable Academy-authored synthetic exercise supplements Stage 17 Lesson 5. The saved lecture remains a controls demonstration with no case PCAP and no packet findings. All addresses, times, jobs and packet contents here are authored training data. Do not treat them as an incident or evidence of authorization.

Keep the whole folder together. Read `collection-notes.md` and `DATA_DICTIONARY.md`, open `practice.pcap` offline, and complete `worksheet.md` before consulting `answer-guide.md`. The baseline is `baseline-synthetic.pcap`. Both are ordinary Ethernet PCAPs. The previous draft name `fanout-synthetic.pcap` maps explicitly to the delivered `practice.pcap`; do not look for a second primary file. All deliverable names are relative to this folder; publication is separately held until approval.

The lecture uses Wireshark 4.4 on Windows 11. These supplemental fixture validation receipts were actually recorded on Ubuntu 24.04.5 LTS Linux with native Wireshark/TShark 4.4.0 in English. No Windows execution is claimed. On Windows open the same PCAPs in Wireshark 4.4 English light theme; menu locations may differ. Start no live capture. Preserve originals and work on copies. A learner's own authorized internal capture remains separate homework; none of these author receipts claims student execution.

## Reproduce offline

Python 3 standard library only; no installation or network required. Use fresh output paths. The scripts refuse overwrite.

```sh
python3 build_fixture.py --scenario scenario.json --capture practice.pcap --output rebuilt-primary.pcap
python3 build_fixture.py --scenario scenario.json --capture baseline-synthetic.pcap --output rebuilt-baseline.pcap
python3 check_fixture.py --scenario scenario.json --capture practice.pcap
python3 check_fixture.py --scenario scenario.json --capture baseline-synthetic.pcap
```

Compare rebuilt bytes with originals using `cmp` on Linux or `fc /b` on Windows. `execution.json` records both actual byte matches, overwrite refusal, structural checks and independent native TShark decoding. `practice.pcap-3.txt` and `baseline-synthetic.pcap-3.txt` contain decoded frame numbers, epoch UTC, direction, ports, flags, raw sequence/ack, commands/status/share and checksums. `*-4.txt` are empty because the executed malformed/bad-checksum filters matched no frames. These tests prove this synthetic byte fixture's consistency, not real product interoperability.

## Inspect the actual packet workflow

Open `practice.pcap`; choose View → Time Display Format → UTC Date and Time of Day. Apply `smb2`, then `smb2 && ip.addr == 192.0.2.110`. The lecture's `192.0.2.10` is a case placeholder; replace it with this lab source. The old `10.77.0.10` draft example does not apply. `ip.addr` keeps both directions. The filter matches 36 primary frames involving four peers, including responses; the backup source has six separate SMB2 frames.

Open Statistics → Conversations → IPv4; enable Limit to display filter. Check four source-peer rows and confirm first direction in actual packets. Clear the filter around each first SMB2 frame to see the preceding three TCP handshake frames. Apply `frame.number == 8`, select that frame and expand SMB2 → Tree Connect Request: inspect `\\192.0.2.120\AcademyLab`. A successful Tree Connect status in this synthetic exchange is not a completed file operation or proof of remote execution. No file data, operator identity or real credential verification is supplied.

Open Statistics → I/O Graphs. Set one graph row's display filter to `smb2 && ip.addr == 192.0.2.110`, interval to 1 minute and Y Axis to Packets. State whether your graph uses relative capture time or UTC alignment. Our actual CLI `*-5.txt` uses bins relative to first TCP packet, 09:00:19.900 UTC, so its primary counts 6,12,6,6,6 differ from the worksheet's wall-clock bins 6,6,12,6,6. This is expected alignment, not extra peers. Native graph screenshots document opened 1-second graphs with the source-filtered SMB2 series enabled; follow these explicit minute settings for the exercise.

Open the baseline separately and repeat `smb2 && ip.addr == 192.0.2.110`, Conversations and graph work. Repeat the workflow on your own authorized capture only after checking collection point, coverage, clock alignment and inventory. Never assume today's source address or jobs apply to your own data.
