# Setup and safe offline workflow

Use an authorized workstation with Wireshark, matching TShark and capinfos, Python 3, and a writable copy of this complete folder. No live network or secrets are required. The capture `fixtures/tls13-visible-handshake-supplemental.pcapng` is already supplied. It contains actual generated loopback traffic between 127.0.0.1:39122 and 127.0.0.1:31441, captured on `lo` with filter `tcp port 31441`. Both endpoints are the same host. `collection-receipt.json` records the real collection and host OS. Never represent it as an Internet investigation.

From this folder run `sh verify-fixture.sh`. It checks the exact file SHA and TShark fields, failing on changed/missing captures. Read `capinfos.txt` and `hello-fields.tsv`. The included execution receipts show what Academy actually ran; their absolute maintenance paths are historical execution locations. Your local relative commands are:

```sh
capinfos fixtures/tls13-visible-handshake-supplemental.pcapng
tshark -r fixtures/tls13-visible-handshake-supplemental.pcapng -Y 'tls.handshake.type == 1 || tls.handshake.type == 2' -T fields -e frame.number -e tcp.stream -e tls.handshake.type -e tls.handshake.version -e tls.handshake.extensions.supported_version -e tls.handshake.ciphersuite
tshark -r fixtures/tls13-visible-handshake-supplemental.pcapng -Y 'tls.record.opaque_type == 23' -T fields -e frame.number -e tcp.stream -e tls.record.opaque_type
```

Open a working copy with Wireshark File > Open. Record capture identifier, SHA, observation point and time range. Apply `tls.handshake.type == 1`, then `tls.handshake.type == 2`; inspect Transport Layer Security in Packet Details, expanding Handshake and Supported Versions. Record exact offers and selections, original frame references and endpoints. Select a hello and find `tcp.stream`; its observed value here is 0. Apply `tcp.stream == 0`, then clear the filter to inspect context. Display filters preserve original frame numbers.

Wireshark 4.2.2 distinguishes `tls.record.opaque_type` for TLS1.3 outer type23 from `tls.record.content_type`. The historical proposed type filter `tls.record.content_type == 23` returned no rows here (`outer-records.tsv`); that does not mean no encrypted records. Use the verified opaque-type filter above and inspect the record label. `native-outer.png` preserves that empty historical view; `native-opaque.png` shows the actual matching packets. No data is rewritten to make the earlier filter succeed.

Native PNGs come from real Wireshark on Ubuntu with the unchanged capture. Packet-list screenshots do not prove every expanded field; use your local Packet Details plus exact CLI dissection. The checksum-offload artifacts possible in a local loopback capture do not imply malicious traffic. Do not infer capture completeness merely from both directions appearing.
