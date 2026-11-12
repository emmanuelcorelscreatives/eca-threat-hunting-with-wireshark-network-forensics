# Setup and verified offline workflow

Use Wireshark and Python 3 on a machine where you may open course files. No administrator privileges, active scan, poisoning tool, live traffic or external resolver is needed. Work in a fresh copy of this entire folder and preserve the original downloaded ZIP. The builder sends no packets. The checker reads files and sends no packets. The supplied addresses are documentation ranges; the one multicast address is the LLMNR group 224.0.0.252.

The exact supplied practice.pcap SHA-256 is:

`5055dd9d6d258d22ae22f30631dce775cfe1c602d2329a94057280ae88e15202`

From this folder, verify and independently rebuild to a new filename:

```sh
sha256sum practice.pcap
python3 check_capture.py practice.pcap fixture-spec.json
python3 build.py --spec fixture-spec.json --output rebuilt-practice.pcap
cmp practice.pcap rebuilt-practice.pcap
python3 check_capture.py rebuilt-practice.pcap fixture-spec.json
```

Do not use Python's `-O` option: the checker's assertions are intentional validation guards. The builder refuses an existing output, including practice.pcap. Choose a fresh output name each time. A byte-identical fresh rebuild was actually performed by the author; execution.json records the absolute author commands. Your machine paths will differ. A successful cmp has no output and exit status zero. The checker expects exactly this versioned scenario; it is not a general detector for arbitrary evidence files. Four altered scratch captures were rejected (truncation, extra bytes, IPv4 and UDP corruption), recorded in raw-check-negative-tests.json.

Open a working copy of practice.pcap with File → Open in Wireshark. Disable external name resolution or use numeric source/destination values; names displayed by the application can come from outside the packet. Set a relative time display or read captured UTC timestamps explicitly. The authored times are synthetic, not a real collection window. Select each request and response, expand the decoded protocol in Packet Details, and compare names, transaction ID, response bit and address records. A port number alone is insufficient. The provided native screenshots show the filters and packet lists, not all expanded details.

Apply these exact display filters one at a time:

```text
udp.port == 5355
nbns
dns && (udp.port == 53 || tcp.port == 53)
tcp
```

Expect 3, 4, 3 and 7 packets respectively. Clear the filter to restore all 17 packets. A display filter hides packets without deleting them. The saved native screenshots document these steps on Ubuntu 24.04 with Wireshark 4.4.0, not Windows. On another version the layout may differ.

Optional command-line cross-checks, actually run in the author environment with the supplied native TShark executable, are equivalent to:

```sh
tshark -n -r practice.pcap -Y 'udp.port == 5355'
tshark -n -r practice.pcap -Y 'nbns'
tshark -n -r practice.pcap -Y 'dns && (udp.port == 53 || tcp.port == 53)'
tshark -n -r practice.pcap -Y 'tcp'
tshark -n -r practice.pcap -Y '_ws.malformed'
```

The last command returned no malformed frames. Exact author arguments, stdout/stderr hashes and platform are in execution.json. fields.stdout.txt supplies names, answers, transaction IDs, raw TCP sequences, flags, zero TCP lengths and checksum status; full-dissection.stdout.txt supplies expanded decoded details. Status 1 in the recorded checksum fields means good in this build. Warnings about the author's root execution account are preserved as historical stderr, not student instructions. Do not transmit any fixture onto a network.
