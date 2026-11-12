# Optional synthetic fixture dictionary

`practice-spec.json` is an independently authored, self-contained teaching example for opening a saved file. It is **not** the unavailable capture in the saved demonstration, a verified copy of the previously proposed `practice/dns-baseline` fixture, or a course investigation case pack. All addresses are documentation-only; names use `.example`. No real sensor or collection-coverage claim is represented.

| Field | Meaning |
| --- | --- |
| `version`, `synthetic` | Builder input version 1; explicit synthetic-data declaration. |
| `fixtureId`, `purpose`, `scope`, `observationPoint`, `sourceLessonProjects` | Authored scenario metadata, not packet-derived evidence. |
| `events` | Ordered source records; one event is designed to produce one packet. |
| `timestamp` | Explicit UTC packet time in the synthetic design. |
| `kind` | Supported `dns-query` or `dns-answer`; builder writes DNS over UDP. |
| `src`, `dst` | Synthetic IPv4 packet source and destination. `192.0.2.10` is the example client; `192.0.2.53` is the example resolver. |
| `sport`, `dport` | UDP source and destination ports; 53 identifies the example DNS service port. |
| `name`, `transactionId` | Designed DNS question and identifier; each answer matches its query. |
| `answer` | Designed IPv4 A-record value, present only on answers. |

The builder supplies packet framing and checksums; it does not turn scenario metadata into observed real-world facts. The actual builder input is `executed-fixture-spec.json`. Actual decoded names, answers, ordering, timestamps and numbering are preserved in both `.fields.tsv` files; these match between the delivered PCAP and converted PCAPNG. `execution-proof.json` records the actual commands, deterministic PCAP rebuild and existing-file refusal. These checks do not establish historical collection coverage or GUI execution.
