# Setup

Use Python 3 standard library, Wireshark/TShark and Capinfos, and sha256sum on a POSIX shell. This kit was executed on Ubuntu 24.04 native Wireshark/TShark 4.4.0; Windows execution is not claimed. Work from this kit directory. The supplied captures are ready to open without a live capture. Compute hashes before copying and preserve the originals.

```sh
python3 --version
tshark --version
capinfos --version
sha256sum captures/*.pcap
mkdir working
cp captures/*.pcap working/
```

Open each working copy in Wireshark. Clear display filters before comparing the whole view. Open Statistics → Capture File Properties. Record metadata as displayed; unknown dropped packets means not available, never zero. Use `frame.cap_len < frame.len`, select the matching record and expand Frame details to compare saved and original lengths. Then clear the filter and compare both endpoint directions and time boundaries. The included native PNGs document these operations on the truncated view, not Windows or other views.

Rebuild offline into a NEW directory (no network access or packet sending):

```sh
python3 build_fixtures.py --output rebuilt
python3 offline_builder.py --spec session-truncated.json --output practice-rebuilt.pcap
cmp practice.pcap practice-rebuilt.pcap
```

Both entry points refuse existing output files. The wrapper generates all three named captures and replaces the earlier draft's missing build_fixtures.py plan. The packaged filename is offline_builder.py. To repeat use a fresh output directory; do not delete or overwrite preserved originals.

For each capture run these checks (these exact TShark filters/fields and Capinfos checks were actually executed for all three captures; actual-execution.json records concrete argv and results):

```sh
for f in captures/*.pcap; do
  capinfos "$f"
  tshark -r "$f" -Y 'frame.cap_len < frame.len' -T fields -e frame.number -e frame.cap_len -e frame.len
  tshark -r "$f" -Y 'ip.addr==192.0.2.10 && ip.addr==198.51.100.20' -T fields -e ip.src -e ip.dst
  tshark -r "$f" -Y '_ws.malformed' -T fields -e frame.number
done
sha256sum captures/*.pcap
```

*-fields.stdout.txt provides actual ordered raw TCP sequence/ACK, payload, time and length observations. The local execution used absolute installed tool paths; PATH commands above use your installation. No live capture or learner homework execution is represented by the author evidence.
