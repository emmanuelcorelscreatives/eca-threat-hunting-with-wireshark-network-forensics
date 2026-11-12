# Worksheet: bound the identity claim

Use `scenario-cards.csv` as **stated hypothetical premises**, not observed packet evidence. Its connection labels are not TCP stream IDs. For each answer, say what the premise permits and what would need verification in an actual capture. There are no frame references to cite for these cards.

1. **Hypothesis:** Did the client advertise `shop.academy.test`, and did that same connection present an identity covering it? Compare C1, C2, and C7. Write separate sentences using **advertised** and **presented**. Does their common destination address establish a visit, one website, or a trust decision? For C7, state the condition under which an identity mismatch could be reported from packets.
2. Compare C3 with C4. Which premise selects TLS 1.3 using ServerHello `supported_versions`? Why is legacy `0x0303` insufficient? Give a different reason a readable Certificate may be absent in each. What would you check before applying either explanation to real traffic?
3. For C5, list the unanswered questions caused by the late start and missing return direction. For C6, distinguish the outer advertised name from an unknown inner name; does an `encrypted_client_hello` extension establish ECH acceptance? Could it be GREASE? For C8, state what cannot be inferred about a QUIC certificate.
4. Draft a two-sentence assessment of one card that does **not** claim a completed visit, application request, certificate acceptance, malicious activity, or an unseen identity. Name the next authorized evidence that would improve confidence.

## Packet-evidence template for the supplied Academy capture

- Hypothesis and capture filename/working-copy provenance: ____
- Observation point, exact time window, setup coverage, both directions: ____
- Wireshark filters/pivots and connection endpoints or TCP stream: ____
- ClientHello frame/time and exact **advertised** SNI, or unavailable: ____
- Same-connection ServerHello frame and selected version evidence, or unavailable: ____
- Same-connection readable Certificate frame and **presented** subjectAltName DNS identities, or unavailable: ____
- Alternative explanations: shared address; late or one-way capture; TLS 1.2 resumption; TLS 1.3 or QUIC protection; ECH visibility/GREASE: ____
- Supported conclusion, confidence limit, and next authorized capture or narrowly relevant endpoint context: ____

A Certificate’s presentation does not establish client trust. A visible SNI is not a URL or proof of an encrypted application request. Leave relationships unresolved when the packets cannot connect them.
## Executed packet tasks

1. Fill the template for stream 0 using ClientHello 4 and Certificate 6; state advertised versus presented identities and a bounded conclusion.
2. Fill it for stream 1 using ClientHello 21 and ServerHello 23. Cite supported_versions and explain certificate visibility without secrets.
3. Use manifest first/last timestamps and port tuples to document both directions and setup. Check checksum-status.csv separately from malformed.txt and file SHA.
4. Rebuild into a new filename and compare SHA. Explain why running the live builder yields different bytes and why shared loopback address cannot pair unrelated messages.
