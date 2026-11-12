# Per-file worksheet

Hypothesis: the same peer relationship in known files need not mean separate sessions or malicious traffic. Read `case-manifest.csv` first. Confirm each original, permitted working copy, stated point, UTC window, and collection limit. Never discover inputs with a directory-wide search. Record installed `tshark -v` and `capinfos -v` output and the selected Wireshark profile.

For **each** working copy, preserve the exact command and output under its source ID. `-r` reads offline, `-C` selects the checked profile, `-n` disables name resolution, and `-q` suppresses packet listings, not requested statistics. Run the individual template with an actual authorized path, then this known-file batch:

```sh
tshark -r "<WORKING_COPY>" -C "Default" -n -q -z endpoints,ip -z conv,tcp -z conv,udp
for f in student-work/s8l3-{a,b,c}.pcapng; do printf 'SOURCE=%s\n' "$f"; tshark -r "$f" -C "Default" -n -q -z endpoints,ip -z conv,tcp -z conv,udp; done
```

The loop does not find, alter, or combine captures. Record profile `Default`, filter `none`, actual analyzed path, both hashes, versions, stated scope, and each file's separate IPv4 endpoint, TCP-conversation, and UDP-conversation tables. Compare TCP only with TCP and UDP only with UDP. IPv6 needs a separate endpoint table and a recorded change of method.

For the fixture's validated comparison expression, run separately for every relevant file:

```sh
FILTER='ip.addr==192.0.2.10'; for f in student-work/s8l3-{a,b,c}.pcapng; do printf 'SOURCE=%s FILTER=%s\n' "$f" "$FILTER"; tshark -r "$f" -C "Default" -n -q -z "endpoints,ip,$FILTER" -z "conv,tcp,$FILTER" -z "conv,udp,$FILTER"; done
```

Record that expression with each scoped output. `-Y` alone does **not** limit these `-z` tables; scoped and unfiltered tables answer different questions. Do not treat a failed command as an empty table.

Per source, fill in: **original path/hash; analyzed path/hash; point/window/limits; versions; profile; filter; exact command; endpoint addresses and directional captured packets/bytes; TCP and UDP peer pairs, directions, relative starts and durations where shown; errors**. In Wireshark, File → Open the **same** working copy; match profile, protocol-layer tab and filter, and check whether Statistics → Endpoints or Conversations limits statistics to the display filter. Note matching or unresolved totals. Inspect representative packets only after opening the files; record actual frame references, or say none inspected. Finish with alternatives, confidence limits, missing telemetry, and the next useful packet or collection-context check.

## Native GUI comparison and representative packets

For each source open your exact `student-work/s8l3-X.pcapng` with File → Open. Clear the display filter. Statistics → Endpoints: select IPv4 and record address/packet/byte totals and directions. Statistics → Conversations: select TCP and then UDP, preserving each file separately. Apply `ip.addr==192.0.2.10` in the main display filter, reopen both dialogs, and verify the visible “Limit to display filter” checkbox is checked. Do not assume a previously saved checkbox state. Compare the three-address scoped endpoint table and one-row scoped UDP table with the matching `-z` command output. To reproduce broad tables while a display filter is active, explicitly uncheck that box and record the change. Do not confuse the Conversations “Absolute start time” checkbox with the filter-limit checkbox.

Select original frame 6 in each file using `frame.number==6`; record actual source/destination tuple, raw sequence and acknowledgment values from Packet Details, and captured length. The filter keeps original frame numbering. Compare A/B timestamps and C's new source port/sequence space using `fields-{a,b,c}.stdout.txt`. Clear the filter afterward. Supplied native screenshots are specific observations, not a claim that every field hidden beyond the viewport was seen.

## Separate authorized-file assignment

With authorization, repeat this full intake, known-file batch, explicit-filter and GUI comparison for three files available to you. Record actual capture-point/window/collection limitations supplied by the owner; leave unknown values unknown. Do not claim this assignment has already been completed by a learner. If such files are unavailable, the shipped synthetic practice remains fully usable, while the separate assignment awaits authorized inputs.

Submit per-file exact commands/results, original and working hashes, versions/profile, GUI comparisons, representative frame observations, a hypothesis with ordinary-traffic and repeated-observation alternatives, confidence limits, missing telemetry and the next useful packet or collection-context check. Never sum overlapping sources as unique traffic.
