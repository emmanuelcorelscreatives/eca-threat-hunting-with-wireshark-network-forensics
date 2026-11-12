# Compare wide and short I/O Graph intervals

This is newly authored synthetic offline Academy practice for Stage 7 Lesson 4, Build Time-Based Views with I/O Graphs. It is separate from the saved lecture, which has no supplied capture and claims no finding. The lecture uses Windows 11 / Wireshark 4.6.0; our executed checks use Ubuntu 24.04 / native Wireshark GUI 4.4.0 and TShark CLI 4.2.2. No Windows execution is claimed.

All addresses are documentation addresses. Packets were constructed offline: no traffic was sent, no actual host was observed, and there is no real collection point, loss counter, process inventory or clock calibration. The file cannot establish production coverage, silence, purpose, software or maliciousness. TCP sessions contain opening handshakes only; a port number does not identify an application. The designed schedule is educational, not a historical incident.

Prerequisites: Python 3, Wireshark, TShark. Work in this directory. Open `practice.pcap` with File > Open. To rebuild without overwriting it:

```sh
python3 offline-builder.py --spec fixture-spec.synthetic.json --output rebuilt.pcap
```

The builder refuses an existing output. A fresh byte-identical rebuild and overwrite rejection were executed; see execution.json. Original capture SHA256: f54456f98aebe0fc9cfa4971b4153cfc60c3f01d63d6390a1910fec7c72b36c3.

1. Open Statistics > Capture File Properties. Record first/last timestamps, duration, packet count and scope limitations. The designed UTC window is 2025-02-03 10:00:00 to 10:00:30.020. A span does not prove uninterrupted real collection.
2. Open Statistics > I/O Graphs. Keep the first graph unfiltered and add a second row with display filter `tcp`. Set Y Axis to Packets for both; use the same Line style, Time of day off (elapsed time), Avg over Time off and SMA Period None. Record actual controls in your installation. Packets counts matching recorded packets per bin; Bytes would include packet headers, not just payload.
3. Compare 10 sec and 1 sec intervals over the entire 30.02 sec window, changing only interval. Keep filter, style, time basis and smoothing fixed. Save both views. Check endpoints: the last group touches the file end and cannot show what follows.
4. Compare all-packet and TCP rows at seconds 7 and 8. Compare one-second versus ten-second bins around seconds 20–22. Wide bins aggregate timing; changing bins never adds packets. Record repeated groups at 0,5,10,15 seconds without assigning software or purpose.
5. In the 1 sec graph click a candidate bin around 20 seconds to navigate to an associated packet. Record the actual selected original frame and inspect nearby timestamps; a hover representative is not every packet. Validate in the packet list with `frame.time_relative >= 20 && frame.time_relative < 22`.
6. Inspect both directions for one candidate using `tcp.port == 51004 && ip.addr == 192.0.2.10 && ip.addr == 198.51.100.20`. Check before/after the interval and record original frames, times, addresses, direction and protocol. Do not infer a transfer from a handshake.
7. Inspect a quiet interval, for example [2,3) sec. Line/bar styles display zeroes; scatter omits points. A TCP zero at [7,8) is not an all-protocol zero. Even an all-packet zero is limited to this constructed file.
8. Complete worksheet.md. Include a routine alternative and a question requiring additional approved evidence. Preserve both interval settings in your note.

CLI checks actually executed, with full retained logs:

```sh
tshark -n -r practice.pcap -q -z 'io,stat,1,tcp,udp'
tshark -n -r practice.pcap -q -z 'io,stat,10,tcp,udp'
tshark -n -r practice.pcap -Y _ws.malformed -T fields -e frame.number
```

The first two logs list TCP and UDP separately; the all-packets count equals their sum in this fixture. They are CLI results, never proof of hidden GUI state. Native screenshots show actual1sec and10sec comparison. The actual graphclick proof uses10sec interval at20sec, hint count24 and associated frame42, then native packet list selection42. This illustrates a representative associated packet, not every counted packet. The attempted return to1sec before the click did not change the control; no1sec click is claimed. Native evidence and its review are supplemental observations of their specifically visible states. Public repository publication follows independent kit approval.
