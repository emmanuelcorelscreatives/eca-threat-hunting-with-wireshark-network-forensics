# Setup

Use an ordinary user account. This is offline file analysis: no live interface, administrator privileges, network traffic generation, or hardware changes are required.

Install Wireshark and, optionally, its TShark command-line component through your approved software source. Python 3 is needed only for deterministic fixture verification/rebuilding; the builders use the standard library. `requirements.txt` intentionally installs nothing.

Open a terminal in the downloaded kit directory containing the supplied captures, builders, specification, and manifest. Commands below assume `python3` and `tshark` are on PATH. On Windows use `py -3` instead of `python3`; if needed invoke TShark as `& 'C:\Program Files\Wireshark\tshark.exe'` in PowerShell instead of `tshark`.

Read captures without saving over them. Do not run `offline-builder.py` with `practice.pcap` as its output: that builder can overwrite its destination. The richer builder refuses existing capture or manifest destinations.

For your own capture homework, obtain authorization first. Avoid credentials, personal content, and third-party traffic; keep originals private and share only approved, minimized evidence. Generating the supplied practice files is not collecting traffic.
