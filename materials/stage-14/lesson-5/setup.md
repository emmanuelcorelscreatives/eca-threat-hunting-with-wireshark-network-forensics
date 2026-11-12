# Setup and reproducible verification

Use Python 3.11+ and TShark/Wireshark with HTTP/2, QUIC v1 and HTTP/3 support. Command evidence in this kit was recorded with system TShark 4.2.2; native screenshots use Linux Wireshark 4.4.0. Newer builds may display details differently. Work inside the downloaded lesson directory, with all files kept together. This offline workflow requires no capture privilege.

1. Inspect fixture-manifest.json and record the capture SHA256, scope and both server ports. This is actual traffic on Linux interface lo, both directions using 127.0.0.1, TCP 18445 and UDP 18446. Capture timestamps are actual collection time, not a historical case date. Loopback checksums contain partial pseudo-header values from offload; this capture cannot validate checksums on a physical wire.
2. Run the verifier. It fails closed on wrong capture/key hashes, absent exchanges, wrong streams, scope, totals, timestamps, malformed or bad-checksum warnings. Its assertions and protocol limits are readable in the supplied source.

```sh
python3 verify-boundaries.py --manifest fixture-manifest.json --capture supplemental-boundaries.pcapng --keylog supplemental-boundaries.keys
```

The expected first field is state PASS. verification-report.json is the actual retained run; do not treat this sentence as proof your run succeeded. Compare your output, version and errors.

3. Open the same supplemental-boundaries.pcapng in a fresh Wireshark profile without a TLS key-log preference. Run http2, quic and http3 separately. Record match or empty result, frame, direction and exact visible fields. The native-without-keys images show the recorded packet-list state. QUIC Initial dissection may expose handshake clues without secrets, but later application payload remains protected. ALPN offered by a ClientHello is not proof of server selection.
4. Configure only the included disposable matching keys as the TLS (Pre)-Master-Secret log filename under Preferences > Protocols > TLS. Reload the same capture. Use the earlier authorized decryption workflow if your Wireshark build labels it differently. Never show the file's contents in screenshots or reports. Repeat all three filters. The native-with-keys views show packet-list results, not expanded field proof.
5. Expand relevant protocol details and record http2.streamid, http2.headers.path/status, quic.stream.stream_id and http3.headers.path/status where decoded. Inspect HEADERS, DATA and end-stream/FIN indicators, not just protocol labels. Use the exact actual CLI output as a comparison; do not claim a hidden GUI field was visible in a screenshot.

The following executed commands are also recorded in cli-execution.json and their output files. The first intentionally has no secrets; the second loads only the matching authorized fixture keys.

```sh
tshark -r supplemental-boundaries.pcapng -Y 'http2 || quic || http3' -T fields -e frame.number -e tcp.stream -e udp.stream
tshark -o tls.keylog_file:supplemental-boundaries.keys -r supplemental-boundaries.pcapng -Y 'http2 || quic || http3' -T fields -e frame.number -e http2.streamid -e quic.stream.stream_id
```

For protocol fields not supported by your build, record the error and version, then use a supported build; do not convert absent output into absence of traffic. To return to a no-key comparison, remove the preference and reload in a fresh profile; do not assume cached decryption has disappeared.

Optional collection: collect-boundaries.py is the actual source used for this owned loopback sample. It needs aioquic 1.7.2, h2 4.4.1, OpenSSL, dumpcap, capture authorization and free local ports 18445/18446. Run a copy in a NEW empty directory; it refuses existing outputs. It generates a temporary self-signed local certificate, local sessions and matching new keys. This is live collection, not a deterministic byte rebuild; every new capture/key pair needs a new measured manifest and review. No internet traffic or production credential is used. The original failed capture-path permission attempt is preserved outside this published kit; this kit contains only the successful capture and its receipts.
