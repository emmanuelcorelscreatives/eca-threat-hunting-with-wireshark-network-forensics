# Setup and downloadable resources

**Required course files:** [worksheet.md](worksheet.md), [answer-guide.md](answer-guide.md), and this [setup.md](setup.md). The worksheet includes the blank observation schema and data dictionary. No packet file or separate CSV is required for the synthetic exercises.

**Optional shared tool:** Download [Wireshark](https://www.wireshark.org/download.html) for packet inspection. TShark is optional and is not needed here. Use an isolated practice workspace without private production data or credentials.

**Optional synthetic input:** The supplied [public course repository](https://github.com/emmanuelcorelscreatives/eca-threat-hunting-with-wireshark-network-forensics) contains `practice/dns-baseline/README.md` and its existing six-packet synthetic DNS fixture. Download from the repository and consult that README for the actual fixture filename. It is supplemental practice, not the saved no-file demonstration or evidence of compromise. No other case capture is supplied.

For optional inspection, choose File then Open and select only your authorized capture or that fixture. Record its collection point and time window. Apply `dns`; clear it to restore context. Inspect questions with `dns.flags.response == 0` and replies with `dns.flags.response == 1`. Enter only fields you can see in the blank log. No commands, control totals, or packet results are claimed as executed in these files.