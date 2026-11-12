# Scenario-card data dictionary

`scenario-cards.csv` is Academy-authored **hypothetical scenario metadata**, not a log, packet capture, certificate inventory, or measurement. The eight rows are design prompts, not a PCAP control total. All endpoints are illustrative loopback labels; `.test` names are reserved examples. `>` identifies the proposed client-to-service connection, not an observed packet direction. `|` separates SAN DNS names. `-` means **not specified**, never proven absent. No row supplies a timestamp, frame, TCP stream, cryptographic secret, or application request.

| Column | Meaning |
|---|---|
| `card_id` | Stable exercise identifier C1–C8. |
| `window_premise` | Whether the hypothetical observation includes setup or begins late. |
| `directions_premise` | Hypothetical bidirectional or client-only coverage. |
| `connection_premise` | Illustrative client and service IP:port endpoints; C8 is UDP/QUIC, others TCP/TLS. |
| `clienthello_premise` | Whether a ClientHello is available in the hypothetical window. |
| `version_premise` | Version or protocol stipulated for reasoning; TLS 1.3 selection explicitly cites ServerHello `supported_versions`. |
| `sni_premise` | Stipulated advertised hostname; C6 names only the outer ClientHello. |
| `certificate_premise` | Stipulated readability, protection, omission, or unknown status—not a parsed certificate. |
| `san_premise` | Stipulated presented subjectAltName DNS identities where the premise supplies a readable Certificate. |
| `ech_premise` | Extension premise and acceptance limit; not a determination of the inner name. |

The delivered `tls-metadata-supplement-manifest.csv` is a separate actual-capture table; hypothetical cards have no one-to-one mapping to its connections. Actual provenance and control values appear in execution.json and capture-info.txt; checksum status is separate.
## Actual capture manifest

The separate tls-metadata-supplement-manifest.csv contains actual TShark4.4 fields: frame.number; frame.time_epoch (UTC epoch seconds); IPv4 source/destination; TCP source/destination ports, stream index and flags; TLS handshake type/version, supported_versions, advertised SNI, and readable certificate SAN DNS names. Empty field means not decoded in that frame, not protocol absence. Comma-separated multiple field values are quoted; stream0/1 are local TShark indices, not identity attribution. execution.json binds source SHA and packet facts.
