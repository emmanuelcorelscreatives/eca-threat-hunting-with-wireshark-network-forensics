# Setup

**Scope:** This no-PCAP method exercise uses nine explicitly synthetic, independent text cards. They are not captured incidents, software output, session findings, or evidence of authorization. No frame numbers, addresses, or timestamps exist; do not add them. Wireshark is unnecessary.

**Required downloads:** `setup.md`, `worksheet.md`, and `answer-guide.md`. No other input, capture, or software is required. Work in that order.

## Card dictionary

- **ID:** Synthetic case identifier.
- **Peers:** `C` is the candidate source; `S` is the candidate destination.
- **Coverage:** Directions and setup portion represented.
- **Evidence:** Only the stated transport, port, decoding, and visible setup.

Choose the strongest supported tier: **port lead** (a port or suggestive clue without decoded remote-service protocol or recognizable setup), **decoded protocol** (the candidate remote service itself is decoded, not just its HTTP/HTTPS carrier), **recognizable setup exchange** (service-specific setup evidence in both directions), or **inconclusive** (no packet-level service clue). An HTTP request/reply with a `wsman` URL prefix can strengthen a WinRM lead but is not, by itself, decoded WinRM or a recognizable remote-service setup exchange. Keep service identification separate from completed login, user, actions, and authorization.