#!/usr/bin/env bash
set -euo pipefail
cd -- "${1:-.}"
sha256sum practice.pcap
capinfos practice.pcap
tshark -r practice.pcap -Y dns -T fields -e frame.number -e ip.src -e dns.qry.name -e dns.qry.type -e dns.flags.response -e dns.flags.rcode
tshark -r practice.pcap -Y 'dns.flags.rcode == 3' -T fields -e frame.number
tshark -r practice.pcap -Y 'ip.addr == 198.51.100.40' -T fields -e frame.number
