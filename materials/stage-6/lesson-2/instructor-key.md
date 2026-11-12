# Instructor key — actual synthetic PCAPNG findings

The supplied PCAPNG was generated and decoded with native TShark/capinfos 4.4.0. It has 17 frames, two synthetic interfaces, one TCP conversation and a 0.2 second interval beginning 2025-01-16 12:00:00 UTC. The SHA-256 is `664b7c77056be09ee73cf979fef4287dcc5b4015f0a58d3d81b2bc0a7189a7cb`. See actual `properties.stdout.txt`, `fields.stdout.txt`, `expert.stdout.txt`, per-filter receipts and `execution.json`. An independently reviewed native Linux Wireshark 4.4.0 Expert Information image is included: “Limit to Display Filter” is checked for `tcp.stream == 0`, and the expected diagnostic summaries are visible. Other GUI captures are retained in production evidence without an independent approval claim. CLI results do not prove hidden GUI fields; this image does not complete every worksheet step for the learner.

## Frame evidence in the PCAPNG

Frames 4 and 5 contain identical Ethernet packet bytes: server 198.51.100.20:40000 to client 192.0.2.10:54000, range `[9001,9009)`, ACK 1001, flags 0x0018, payload `ABCDEFGH`. Interface IDs differ (0 and 1), timestamps differ by one microsecond. The supplied generator deliberately clones frame 4 to interface 1; this proves a construction artifact in this fixture, not two sender transmissions. Interface names and close timing alone in an unknown real capture would be weaker evidence requiring collection provenance.

Frame 6 carries `[9009,9017)`. Client ACKs in frames 7–10 remain 9001. Frame 11 repeats `[9001,9009)` on interface 0 at 0.095 seconds; frame 12 ACKs 9017. Frame 13 carries `[9025,9033)` before frame 15 supplies `[9017,9025)`; frame 14 ACKs 9017 and frame 16 ACKs 9033. This is observed file order, not proof of actual receiver arrival order or network loss. Frame 17 is a client-to-server RST+ACK with ACK 9033. The capture cannot establish why it was sent or whether the receiver accepted it.

Actual version 4.4.0 filter results, independently runnable from the included files:

| Filter | PCAPNG frames |
| --- | --- |
| `tcp.analysis.retransmission` | 5, 11 |
| `tcp.analysis.lost_segment` | 13 |
| `tcp.analysis.duplicate_ack` | 7, 8, 9, 10, 14 |
| `tcp.analysis.out_of_order` | 15 |
| `tcp.analysis.fast_retransmission` | 11 |
| `tcp.flags.reset == 1` | 17 |

Frame 11 may satisfy both retransmission filters; do not add those counts as unique events. Different decoder versions/preferences may classify differently. The native expert summary records suspected retransmissions, a missing-segment warning, duplicate ACKs, suspected out-of-order data and a reset. None is an intrusion verdict or proof of sender algorithm. The empty `malformed.stdout.txt` applies to the PCAPNG only; the original PCAP malformed receipts remain in production history rather than as distinct retained files in this release. Do not treat this one release receipt as independent evidence for both files. This is a dissection result, not proof of a real-world healthy path.

A good report describes repeated data and ACKs, observed-order gaps, the known construction duplicate and reset direction. Loss is plausible for an analogous real trace, but receiver delivery, collection loss, observation position and reordering require other evidence. Seek collection-health records, a second authorized observation point, and endpoint/application context. Award credit for raw ranges and ACK arithmetic, both-direction context, original file/frame provenance, wider-window checks, candid no-match results where applicable, uncertainty, a credible alternative and a discriminating next step. Treating any diagnostic flag as proof of intrusion, network failure or application completion fails the evidence standard.
