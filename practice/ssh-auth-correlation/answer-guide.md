# Answer guide — controlled SSH exercise

## Packets

The supplied `ssh-auth-practice.pcap` has SHA-256 `7816d517c4d6db670421d1d1ba60d4926ba3bf2efb6e9f9878790936b395a79c`, 27 frames and one TCP stream (`0`). The classroom pair is client `198.51.100.25:32926` ↔ server `192.0.2.22:22`. Frames 1, 2 and 3 contain the opening TCP SYN, SYN/ACK and ACK. Frames 4 and 6 expose SSH identification strings; later SSH data is encrypted. Both directions occur (15 client-to-server frames and 12 server-to-client frames). The observed span is **2026-11-12 01:33:30.340406 UTC through 01:33:30.634144 UTC**, duration **0.293738 seconds**. No FIN/RST session closure is in these captured frames. The broader collector/client execution interval is not evidence that every packet during it was retained.

The `ssh` filter selects frames 4, 6, 8, 9, 11, 12, 14, 16, 18, 20, 21, 22, 23, 24, 25 and 26. It omits TCP-only traffic, including the opening handshake. `tcp.stream == 0` selects all 27. `tcp.port == 23` selects zero; this only answers that condition in this file and cannot disprove access elsewhere or in unrecorded portions.

## Server records and mapping

`AUTH-006` is the actual accepted-public-key record, account `root`, raw source `127.0.0.1:32926`, raw destination `127.0.0.1:50919`. Its journal **collector receipt** is `2026-11-12T01:33:30.593367+00:00`. The native embedded event timestamp is not available. Do not silently relabel receipt time as the authentication instant. Nearby `Accepted key` checks AUTH-003 and AUTH-005 are not extra successful-login events. Eleven records belong to this unique lab daemon tag; other PAM/system sources were not exhaustively collected.

`training-address-map.csv` documents offline endpoint replacement, not observed translation or historical address assignment: raw client `127.0.0.1:32926` became `198.51.100.25:32926`; raw server `127.0.0.1:50919` became `192.0.2.22:22`. The actual transformation retains packet payloads, order, timestamps, sequence numbers and options and changes headers/checksums only. This controlled chain permits comparing these **exercise** endpoints. It supplies no real machine owner, DHCP lease or NAT transaction.

## Inference and limits

A supported classroom conclusion is: one captured bidirectional SSH conversation with an opening handshake is consistent with this one accepted account record after applying the explicit offline mapping. The receipt timestamp falls inside the observed packet interval on the same lab host, and the unique raw source port/destination agree. No external clock calibration or bound on journal delay was measured; time proximity alone would not establish the link. The provenance of this controlled collection strengthens the exercise-specific relation; it must not be generalized to a different case.

An ordinary explanation is the deliberately restricted Academy lab action described in `lab-execution-context.json`. That separate execution context is not a historical business authorization record and does not identify the human operator from the packets. The packets do not reveal account authentication success or the encrypted command. The authentication record does not prove who physically operated the client, business authorization, intent or maliciousness. Client exit status and forced-action output are separate lab evidence, not decrypted packet findings.

For a real case lacking this controlled provenance, request the historical address/port assignment, relevant translation mapping if any, measured clock offsets and destination authentication coverage for a narrow interval. If several records fit, retain them as candidates. A missing or empty excerpt cannot disprove an observed connection when logging coverage is unknown. No Windows 4624/logon-type claim can be made from this SSH dataset.
