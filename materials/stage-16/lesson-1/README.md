# Start from a weak indicator and expand carefully

This separate Academy synthetic practice implements the saved weak-indicator design. It is not the unavailable narrated case and establishes no command-and-control finding. Keep the original capture intact and work on a copy. Nothing in this package sends traffic or captures a live interface. The private addresses belong only to this offline fixture; no authorization to contact them is implied.

Read setup.md, complete worksheet.md, then compare answer-guide.md. Python 3.10 or later and native Wireshark/TShark 4.4 are sufficient; the builder and checker use the standard library. No pip dependency, account or network installation is needed. The earlier proposed Scapy installation is superseded by this complete dependency-free implementation.

The package root replaces the earlier proposed `practice/weak-indicator-expand` directory: README.md is the setup entry, DATA_DICTIONARY.md is the data dictionary, answer-guide.md is expected-results, tools/build_capture.py and tools/check_capture.py implement the named tools, and practice.pcap is the named weak-indicator-synthetic capture. These explicit aliases refer to one file per artifact and one exact capture, rather than competing copies. scenario.json retains the proposed packet design and addresses; the unsupported claim that its HTTP exchange was benign has been corrected to synthetic. The separate DNS-baseline example is unchanged and must not be combined with this capture as incident evidence.

Collection context: fictional Academy training alert; designed client-facing isolated link; UTC PCAP timestamps; no actual alert, production sensor, process ownership, agent baseline, NAT mapping or continuous coverage evidence. The recorded first and last packets bound sparse examples, not proof that the sensor observed everything between them.

The local kit has actual executed rebuild, TShark, raw checksum, corruption-rejection and native GUI evidence. Repository URLs and commits are supplied separately after publication; local evidence is not publication approval.
