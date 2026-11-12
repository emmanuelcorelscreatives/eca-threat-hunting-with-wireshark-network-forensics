# Setup and preserve the evidence

Download the entire lesson ZIP and extract it into a writable practice directory. Keep an untouched original copy. All links and commands here are relative to the extracted lesson directory; this kit has no shared dataset dependency. Obtain Wireshark from https://www.wireshark.org/download.html using the package appropriate to your operating system. The GUI exercise requires Wireshark; optional CLI verification requires TShark; optional rebuild requires Python 3 standard library only. Check their versions with `tshark --version` and `python3 --version`. No capture driver or administrator privileges are required to open these offline files. Linux may name the Python command `python3`; Windows may use `py -3` instead.

1. Open `supplemental-manifest.json`. Compare both downloaded PCAP SHA256 values and sizes with it before working. For example run `sha256sum supplemental-edge.pcap supplemental-internal.pcap` on Linux, or `Get-FileHash supplemental-edge.pcap -Algorithm SHA256` and the equivalent internal command in PowerShell. A mismatch is a hold: restore the original download rather than interpret changed evidence.
2. Copy both PCAPs to a working directory. In Wireshark select File → Open for the edge copy, then Statistics → Capture File Properties (the Properties name/location can vary by build). Compare file format, packet count, first/last times and linktype with the manifest. Repeat for the internal copy. Filesystem size, packet bytes and any native summary counter are distinct units; do not infer collection completeness from size. In the recorded Linux Wireshark4.4 classic-PCAP implementation a summary counter can be16 bytes below filesystem size.
3. Set View → Time Display Format to UTC date/time if available. Record the format actually shown. The manifest and CSV originals explicitly use synthetic UTC; there is no evidence-backed clock correction to apply. Preserve each original time and write `no correction, common specified UTC` separately. Do not infer a measured real sensor clock accuracy from this fixture.
4. Record observation points, bidirectional availability and intervals from the manifest. The edge observation is deliberately unavailable from10:05:00 to10:06:00 UTC. The internal interval10:03:20–10:03:50 does not overlap that gap. No host record covers the gap. Lack of packets within it cannot establish inactivity.
5. Verify mapping validity before assigning an asset name. I1 maps192.0.2.10 toWS-A at both observation points from09:00 to11:00 UTC; no translation is specified. I2 and I3 describe the other assets. These are explicit synthetic ledger records, not deductions from an address match.

Optional reproducible checks, from the extracted directory:

```sh
tshark -r supplemental-edge.pcap -Y 'http.request' -T fields -e frame.number -e frame.time -e ip.src -e http.request.full_uri
tshark -r supplemental-edge.pcap -q -z conv,ip
tshark -r supplemental-internal.pcap -q -z conv,ip
python3 offline-builder.py --spec edge-spec.json --output fresh-edge.pcap
python3 offline-builder.py --spec internal-spec.json --output fresh-internal.pcap
```

The output filenames must be fresh: the builder refuses existing paths and sends no packets. Compare rebuilt bytes with the originals using `sha256sum` or `Get-FileHash`; expected hashes are in the manifest. The supplied `rebuild-proof.json` records an actual identical rebuild and refusal test. Retain both originals; do not change an input specification to make a worksheet answer fit.
