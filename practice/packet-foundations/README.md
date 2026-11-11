# Offline packet foundations

Emmanuel Corels Academy · Threat Hunting with Wireshark: Network Forensics

These are **new supplemental synthetic exercises**, not the missing case files mentioned in the saved lessons, production captures, or evidence of an actual attack. The three specifications contain authored packet events. The generator writes bytes to disk and sends no traffic. No credentials, malware, private capture or API access is needed.

## Open and use

Download this complete directory. In Wireshark, choose **File → Open** and select the matching file in `captures/`. Clear the display filter before describing the full file. Record the actual display time zone when quoting clock times. The packet timestamps are fixed UTC values; UI display settings can show them differently.

| Fixture | Matching exercises | Actual verified frames |
|---|---|---:|
| [network-story.pcap](captures/network-story.pcap) | [Network story](lessons/network-story.md) | 6 |
| [tcp-http-download.pcap](captures/tcp-http-download.pcap) | [Evidence boundaries](lessons/evidence-boundaries.md), [TCP sequence](lessons/tcp-sequence.md), [HTTP sequence](lessons/http-sequence.md) | 13 |
| [udp-icmp.pcap](captures/udp-icmp.pcap) | [UDP and ICMP](lessons/udp-icmp.md) | 8 |

Each exercise has blank learner fields followed by a separately labelled answer key. Complete your observations before reading the key. [The schema and data dictionary](DATA_DICTIONARY.md) explain the synthetic inputs and evidence limits.

## Reproduce without overwriting a supplied capture

Python 3 standard library is sufficient for generation. These commands run from the repository root, after choosing a new scratch output directory:

```sh
python3 practice/packet-foundations/build_capture.py --spec practice/packet-foundations/specs/network-story.json --output scratch/network-story.pcap
python3 practice/packet-foundations/verify_capture.py --spec practice/packet-foundations/specs/network-story.json --capture scratch/network-story.pcap --output scratch/network-story-verification.json
```

Use `tcp-http-download` or `udp-icmp` in those paths for the other fixtures. The verifier additionally requires TShark on PATH; it fails on mismatches and refuses to overwrite its JSON receipt. Learners can open the supplied PCAPs without Python or TShark. The recorded maintainer checks used TShark 4.2.2; this is an actual validation tool version, not a claim about the different versions pictured in the saved lectures.

The verifier independently decodes packet fields with TShark, checks endpoints, timestamps, checksums and malformed packets, and compares deterministic regeneration. For the HTTP fixture it also exports the inert text object into an automatically removed temporary directory and compares its bytes. [Verification receipts](verification/) contain the actual decoded fields and capture hashes. These checks do not prove real collection completeness, legitimate purpose, a person, host execution or compromise.
