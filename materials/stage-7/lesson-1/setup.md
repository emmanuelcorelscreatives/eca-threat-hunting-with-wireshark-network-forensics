# Establish the environment and asset roles — practice setup

This complete kit is a separate Academy-authored **synthetic** role-mapping exercise. The saved lecture had no supplied inventory or opened capture. These files do not reconstruct a historical incident or identify real assets. No network packets are sent. Use the supplied captures in an isolated practice directory and keep the original files unchanged.

You need Wireshark, Python 3 for the optional offline rebuild, and TShark/capinfos/editcap for the command checks. Local validation used native Linux Wireshark tools 4.4.0; this is not a Windows execution claim. Open `synthetic-role-baseline.pcapng` directly; `practice.pcap` holds the same 15 synthetic packets in classic PCAP format. `synthetic-role-events.json` is the supplied builder input; `offline-builder.py` is included beside it. No external builder download is needed.

From this directory, you may rebuild to a new, nonexistent output path:

```sh
python3 offline-builder.py --spec synthetic-role-events.json --output rebuilt-practice.pcap
editcap -F pcapng rebuilt-practice.pcap rebuilt-role-baseline.pcapng
capinfos -c -a -e synthetic-role-baseline.pcapng
tshark -n -r synthetic-role-baseline.pcapng -q -z endpoints,ip -z endpoints,ipv6
python3 -m json.tool synthetic-capture-context.json
python3 -m json.tool expected-results.json
```

The bundled PCAP was actually rebuilt byte for byte into an empty scratch directory, and the builder refused an existing output without changing it. The bundled PCAPNG conversion, capture properties, endpoint and malformed-frame queries were actually executed; see `execution-proof.json` and saved stdout/stderr. JSON and CSV validation are also recorded. New rebuild filenames are learner outputs, not bundled artifacts. JSON parsing alone does not validate packet content.

In Wireshark, use **File → Open** on a working copy of `synthetic-role-baseline.pcapng`. Select **View → Time Display Format → UTC Date and Time of Day** when comparing packet timestamps. Open **Statistics → Capture File Properties** and compare first/last packet times with the separate context and inventory validity intervals. Capture-time display can depend on local timezone settings. Record missing collection details. The scenario describes an offline synthetic feed, not an observed workstation or gateway tap.

Clear the display filter. Open **Statistics → Endpoints**, choose **IPv4**, and keep **Limit to display filter** unchecked. Compare IP addresses with inventory records valid for the packet window. Check IPv6 too when present; this file contains no IPv6 packets. TCP/UDP rows include ports; Ethernet labels and name resolution are different evidence. Neither role nor ownership follows from an address, name, manufacturer label or service port. Keep name-resolution settings recorded; the command evidence uses `-n`.

Complete `worksheet.md` and `role-mapping-worksheet.csv`, then compare with `answer-guide.md` and `expected-results.json`. The GUI instructions are learner tasks; saved CLI proof does not establish that a student performed them. For a separate authorized file, use `authorized-file-assignment.md`; its results must remain separate from this synthetic exercise.
