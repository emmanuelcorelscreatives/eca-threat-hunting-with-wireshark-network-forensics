# Analyze Failed and Partial Connections — complete supplemental lab

This separate, explicitly synthetic Academy exercise supplies six worked cases A–F. The saved lecture supplied no PCAP and no historical finding; its method remains unchanged. This generated sample is not a recording of real hosts or a learner's own traffic. Authorization and intent cannot be established from these bytes.

Start with [setup.md](setup.md), complete [worksheet.md](worksheet.md), then compare [answer-guide.md](answer-guide.md). [DATA_DICTIONARY.md](DATA_DICTIONARY.md) describes the CSV plan and synthetic identities. `failed_partial_synthetic.pcap` is the complete 14-frame Ethernet/IPv4/TCP/ICMP practice. The original historical TCP-only subset is not included and must not be confused with this file.

The generator and independent raw-byte verifier use Python's standard library and perform no network operations. The kit includes actual command outputs, execution receipts and four actual Linux Wireshark 4.4 filter screenshots. Screenshots establish only visible filter views, not expanded ICMP quotations, a Windows run, or main-video approval. Verbose TShark output and the independent reader establish the quoted bytes. Versions and stderr are retained, including harmless root-user warnings. The Windows installation workflow has not been executed here.

`current-kit-inventory.json` binds every other delivered file by SHA-256 and byte length. It omits its own hash to avoid recursion. All files are flat in this directory; commands below run from this directory. No older planned `practice/...` directory layout or alias is required.
