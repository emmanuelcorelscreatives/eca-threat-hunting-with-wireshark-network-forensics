# Synthetic scenario dictionary

`http-header-form-scenario.json` is an explicitly synthetic version-1 input for the supplied offline builder. Its `events` are authored design data, **not observed frames**. All timestamps are UTC on 2025-02-20; the modeled window runs from 10:00:00 through 10:00:03.030000. The modeled observation point is an isolated synthetic link, not measured real-world coverage.

| Identifier | Meaning |
|---|---|
| `192.0.2.10` | Documentation-network client |
| `198.51.100.20:80` | Documentation-network HTTP server |
| `forms.academy.test` | Reserved synthetic Host value; no DNS resolution is needed |
| Client ports 51001–51004 | Independent designed TCP conversations; respectively ordinary form, contradictory declarations, multipart, and capture-window limit |
| `SyntheticBrowser/1` | Invented User-Agent claim, not an identified application |
| `academyB1`, `note.txt` | Multipart boundary and sender-supplied filename text |

Each TCP event has a timestamp, direction (`src`, `dst`, `sport`, `dport`), `flags`, absolute `seq` and `ack`, and UTF-8 `payloadText`. The builder constructs Ethernet/IPv4/TCP and PCAP records offline. `Content-Length` declares a byte count; in complete cases it matches the modeled body. The frame 4 request and frames 10/11 bodies have no trailing newline; the frame 5 and 17 response bodies do. The final headers declare 18 bytes that are not supplied; the final conversation deliberately has headers but no modeled body or HTTP response. Distinct client ports are case identifiers, not user identities. No private records, credentials, executable payloads, or shared-course fixture identifiers are used.