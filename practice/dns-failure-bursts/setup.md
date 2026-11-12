# Setup and reproducible checks

Download the entire kit with its directory structure. Use a local working directory you own. This offline exercise needs Python 3 (standard library only) and Wireshark 4.6 with TShark. The Academy actually ran Python 3 and Wireshark/TShark 4.6.9 on Ubuntu 24.04.5; inspect `host-platform.txt`, `tshark-version.txt`, `verification.json`, and `builder-safety-and-rebuild-execution.json`. No Windows validation is claimed. The lecture's Windows 11 platform remains its original context; menus may differ on another platform.

The two PCAPs are already supplied. `generate.py` refuses to overwrite an existing capture. For a reproducibility check, create a NEW sibling output directory, not `fixtures`:

```sh
python3 --version
tshark --version
python3 generate.py --spec fixture-spec.json --out-dir rebuilt-fixtures
python3 verify.py --spec fixture-spec.json --client rebuilt-fixtures/client-facing.pcap --upstream rebuilt-fixtures/upstream.pcap --tshark tshark
```

These exact argument structures were executed by the author with absolute local paths and the retained TShark 4.6.9 binary. Both rebuilt PCAPs were byte-identical; existing-file refusal and four deliberately corrupt scratch captures were rejected. `verify.py` independently parses the raw captures without importing the generator. It checks order, timestamp, endpoints/ports, DNS questions/flags, A records/SOA fields, all lengths, every IPv4/UDP checksum and EOF, then runs TShark with checksum checking and rejects malformed frames. Its decoded CSV and stderr files are written beside the captures under test. Preserve the supplied files and use a fresh output directory if you need a second run.

On Windows, use your installed Python launcher and the full path to TShark; for example the following is a portable usage example, not an observed Windows run:

```powershell
py -3 generate.py --spec fixture-spec.json --out-dir rebuilt-fixtures
py -3 verify.py --spec fixture-spec.json --client rebuilt-fixtures/client-facing.pcap --upstream rebuilt-fixtures/upstream.pcap --tshark 'C:\Program Files\Wireshark\tshark.exe'
```

Open `fixtures/client-facing.pcap` and `fixtures/upstream.pcap` SEPARATELY in Wireshark. Record each collection point, first/last packet and time basis. The author set process timezone UTC; for your display select a clear time format and state it. Relative times begin at the first packet in each file. The upstream first packet is 10 ms later than the client-facing first packet. Collection windows and roles come from authored metadata, not independent endpoint identification.

For each file: apply `dns`; compare queries with replies; apply `dns.flags.response == 1 && dns.flags.rcode == 3`; then inspect the NOERROR zero-answer AAAA response using `dns.flags.response == 1 && dns.flags.rcode == 0 && dns.count.answers == 0`. Expand its DNS details, Questions and Authoritative nameservers. Apply `dns.retransmit_request || dns.retransmission`, and manually compare any matched query to the earlier one. Clearing the filter must restore 22 or 10 frames respectively.

Open Statistics > DNS > DNS (the submenu structure is visible in this recorded build). Inspect response-code, query-type and Response groups together. DNS Statistics may count query and response packets together: do not read its rcode "No error" total as a successful-answer count. The actual client-facing dialog shows 22 total packets, Query 12, Response 10, A 20 and AAAA 2 packet occurrences; this means 11 A queries and one AAAA query, not 20 distinct A lookups.

Open Statistics > I/O Graphs. Disable the default TCP Errors series. Rename All Packets to NXDOMAIN replies, set its Display Filter to `dns.flags.response == 1 && dns.flags.rcode == 3`, keep Y Axis = Packets, and compare equal `1 sec` and `200 ms` intervals. The recorded 4.6.9 dropdown actually offers 200 ms. Record the interval and units shown in your version; a rate-normalized graph is not interchangeable with packet counts per bin. A peak locates transactions, not an application.

Actual CLI checks are retained as each view's `*-nxdomain.txt`, `*-nodata.txt`, and `*-retransmission.txt`, with exact argv/exit status and output SHA in matching execution JSON. To reproduce a filter manually:

```sh
tshark -n -r fixtures/client-facing.pcap -Y 'dns.flags.response == 1 && dns.flags.rcode == 3' -T fields -e frame.number -e dns.id -e dns.qry.name -e dns.response_to
```

Run it separately for the upstream file. The saved CLI and native evidence validate this supplied exercise only; no process identity, configured suffix list, resolver cache hit, Windows run, or historical case is inferred.
