# Offline selection practice

**Status:** Complete locally executed synthetic supplemental lab, pending independent review and public publication. `practice.pcap` is included, not a live or historical case capture. The original lecture's `authorized-working-copy.pcapng` is an illustrative filename; this independent fixture uses its actual PCAP format and `practice.pcap` name. Never rename PCAP bytes to PCAPNG.

Intended public repository directory: `practice/translate-gui-filter-tshark/` in the Academy Wireshark repository. Publication and download attachment are separate release checks; this package does not claim they have already happened. The supplied files are sufficient locally. Wireshark and TShark are the learner prerequisites. Python 3 is needed only for optional local verification or regeneration.

The included `offline-builder.py` and `fixture-plan.json` produced the supplied 498-byte capture and an identical second build. Optional rebuild: first create a new empty directory, then run `python3 offline-builder.py --spec fixture-plan.json --output NEW_EMPTY_DIRECTORY/regenerated.pcap`. The builder can overwrite its output; never point it at any existing capture. The included `verify-kit.py` uses a temporary directory and does not overwrite the supplied capture. Run `python3 verify-kit.py` with TShark on PATH (or `python3 verify-kit.py --tshark /actual/path/to/tshark`).

Actual local validation used Wireshark/TShark 4.4.0 on Ubuntu Linux, not Windows. Command logs and native GUI screenshots are included. The separate opening read-filter field was empty. The unchanged capture showed six total frames; display filter `tcp` showed frames 2, 4 and 6, agreeing with TShark's selected frame numbers. These results apply only to this exact fixture, not another authorized capture. Root TShark emitted its standard privilege warning in stderr; commands completed successfully. No live capture was started.

Learner procedure: record the downloaded capture’s actual path and a locally computed SHA-256 identity; keep that file unchanged. In Wireshark, choose **File > Open**, select it and leave the separate **read-filter** field empty. Confirm the filename and total **Packets**. Validate `tcp` in the display-filter toolbar, then apply it. Record **Displayed** and the ordered **No.** values. On the same workstation, substitute your actual path in:

`tshark -r "practice.pcap" -Y "tcp"`

`tshark -r "practice.pcap" -Y "tcp" -T fields -e frame.number`

The second command makes frame-number comparison easier; the first is the lesson’s summary view. `-r` reads the saved file; `-Y` applies its display filter. Do not substitute `-f`, which specifies a capture filter. The narration’s `tshark -r "authorized-working-copy.pcapng" -Y "tcp"` remains an illustrative command, not a provided file or result. For another authorized working copy, use the expression already validated for *that* question, not necessarily `tcp`. Do not collect or combine traffic. Record the installed tool versions and recheck file identity after comparison.
