# Verified Academy answer guide

These are observed results for this separate supplied Academy fixture, not results from the saved no-file lecture or a learner's capture. CLI evidence is in the exact adjacent output files; native PNGs have narrower Linux packet-list roles.

- Capture contains 15 Ethernet/TCP frames and one TCP stream, 0. UTC window starts 2025-01-16 12:00:00 and ends 12:00:01.400000.
- Client 192.0.2.10:54000 talks to 198.51.100.20:443. This is synthetic transport of real OpenSSL TLS1.2 records, not a captured network incident.
- With empty TLS key-log preference, TLS records are recognized and `http or http2` returns no rows. Follow TLS output contains no decoded exchange.
- With the matching key log, original frame 12, stream 0, client → server, decodes `GET /academy/tls-check`; original frame 14, stream 0, server → client, decodes response 200. `follow-after.txt` contains both request and response and the body `Academy controlled TLS check OK`.
- The exact file SHA256 and separate key-log SHA256 are in `verification.json`. PCAPNG block inspection found no type-10 Decryption Secrets Block. The key log is separate, disposable and intentionally public for this synthetic exercise; restrict real case equivalents.

A strong learner answer records the exact capture hash, before view, authorized key origin, same stream/endpoints, both original frames and expected fields, limits, filter cleanup and preference cleanup. It does not infer user identity, process, intent, or a different action. Failed decryption remains inconclusive until further evidence; empty application rows alone do not identify the failed prerequisite.
