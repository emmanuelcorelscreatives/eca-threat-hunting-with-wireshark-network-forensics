# Worksheet — visible TLS handshake

**Hypothesis:** Paired, decoded hellos in one TLS-over-TCP conversation can show offers and selections; an outer Application Data label cannot establish an application request.

## Part A — hypothetical cards, hypothetical reasoning

Using `example-cards.csv`, identify (1) the offer, (2) the selected version and cipher, (3) what the legacy version does **not** establish, and (4) one claim the outer record label cannot support. State why none of these cards can be cited as observed frames.

## Part B — Wireshark, supplied actual Academy loopback capture

1. Note original capture identifier: ___; working-copy name: ___; actual observation point: ___; verified time range: ___. State whether traffic could have passed that point and whether coverage is uncertain.
2. Apply `tls.handshake.type == 1`. For each ClientHello, record original frame ___, timestamp ___, addresses and ports ___, exact displayed supported-version and cipher-suite offers ___, and source file ___. Write “not visible in this view” for absent fields.
3. Apply `tls.handshake.type == 2`. Record the same identifiers for each ServerHello, plus its exact selected cipher suite and `supported_versions` selection, if decoded. A TLS 1.3 ServerHello's legacy version `0x0303` alone does not establish TLS 1.2.
4. Pair candidates by endpoints and timing. Read `tcp.stream` from Packet Details and filter on its **actual integer value**, not a placeholder. Do both hellos appear in that stream? ___ If not, leave the negotiated result inconclusive.
5. Clear the filter and inspect packets around both hellos. Note directionality, a mid-conversation start, missing traffic, or a cut-short record. Apply `tls.record.opaque_type == 23` for this recorded decoder and inspect the outer Application Data label. Cite its original frame only if decoded. What does its label fail to prove? ___
6. Write one investigation note separating **observed fields**, **protocol inference**, **alternative capture or decoding explanations**, **unsupported process/user/content claims**, confidence, and the next useful action. If a hello is absent, check scope and nearby traffic rather than inventing it.

These filters and the stream pivot address TLS over TCP, not QUIC. Do not assess server names or certificates beyond the visibility distinction needed here; the next lesson examines them.

## Part C — capture scope and a separate authorized practice

Use the supplied file first. Record whether SYN, SYN/ACK, FIN and both directions are present, and why their presence is insufficient to prove lossless collection. Contrast an encrypted-message visibility limit with a capture gap. On a different authorized TLS-over-TCP training capture, repeat the same steps and provide its own identifier, observation point and time window. This assignment has not been performed for a learner. If no such capture is available, submit only the supplied worked practice and mark the separate assignment pending. Do not collect third-party traffic or substitute QUIC.
