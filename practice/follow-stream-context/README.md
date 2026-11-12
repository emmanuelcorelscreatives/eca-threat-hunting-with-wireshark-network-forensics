# Follow Streams Without Losing Context

This complete supplemental lab uses two explicitly synthetic offline captures. They are not the historical capture in the saved lesson. No network packets are transmitted. Keep TCP and UDP files separate; each has its own capture-local stream index. This lab preserves the lesson's full workflow: state a hypothesis, retain the prior filter, inspect combined and directional content and Hex, return to packet times and directions, test Close and Back, inspect adjacent context, and separate observations from assumptions.

Download and extract the whole ZIP. Keep every file in one directory. Requirements: Python 3.11+, Wireshark desktop with matching TShark and capinfos 4.4 or later. Actual included execution evidence uses Ubuntu native Wireshark/TShark 4.4.0. Other platforms may place controls differently; verify visible states.

Start with setup.md, fill worksheet.md, then compare with answer-guide.md. tcp.pcap and udp.pcap are ready to open. offline-builder.py and the two JSON specifications reproduce them with the Python standard library. CLI logs, execution receipts and actual native screenshots are included. This package makes no claim about a real person, process, application response or incident.
