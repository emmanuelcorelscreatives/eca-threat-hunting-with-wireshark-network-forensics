# Synthetic practice data dictionary

`fixture-spec.json` is **authored scenario data**, not an observation of a network. The supplied offline builder accepts its version-1 `events` and produces Ethernet/IPv4 PCAP records with microsecond timestamps. No packets are sent. The capture contains no TLS exchange, credentials, host-identity logs, or measured collection coverage.

| Spec field | Meaning in this fixture |
|---|---|
| `timestamp` | Explicit UTC event time. Wireshark’s Date and Time of Day display uses the viewer’s local time zone; Automatic precision uses the loaded capture. |
| `kind` | `dns-query`/`dns-answer` over UDP, `tcp`, `icmp-echo`, or `icmp-reply`. |
| `src`, `dst` | Documentation-only IPv4 addresses. `192.0.2.10` is labelled the practice client, `192.0.2.53` the practice DNS endpoint, `198.51.100.44` a practice peer, and `203.0.113.8`/`.9` other practice peers. These labels are scenario metadata, not verified host identities. |
| `sport`, `dport` | UDP/TCP ports; DNS uses 53, one TCP conversation uses 443, and another uses 8080. Port 443 does not imply TLS or authorization. |
| `name`, `transactionId`, `answer` | Synthetic DNS question `profile.academy.test`, matching transaction ID, and authored A-record answer `198.51.100.44`. A DNS answer alone does not show subsequent application use. |
| `flags`, `seq`, `ack` | TCP SYN, SYN-ACK, ACK design and corresponding sequence/acknowledgment numbers. Conversations are independent. |
| `identifier`, `sequence`, `payloadText` | Matching synthetic ICMP echo identifiers and harmless text. |

The `tcp.stream` custom column is a Wireshark-derived conversation index, not a fixture field or risk score. Built-in Number, Time, Source, Destination, Protocol, Length, and Information column types should be recorded as configured; do not substitute a similarly titled custom field without documenting it. Observed supplemental frame fields, labels and indices are supplied in decoded-fields.csv; exact execution and native transfer provenance are separately recorded. These are not original-case findings.