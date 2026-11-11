# Setup and Evidence Boundary

## Required downloads
- `setup.md`: prerequisites and measurement limits.
- `worksheet.md`: blank assessment and synthetic exercises.
- `answer-guide.md`: reasoning key; consult after completing the worksheet.

No case capture or saved traffic record is supplied. The worksheet scenarios are **SYNTHETIC EXERCISES—NOT PACKET-DERIVED**. They describe declared facts, not captured incidents. Packet-free completion requires no network access, DNS fixture, credentials, or additional data.

## Optional capture workflow
Use only your own authorized offline capture with locally available Wireshark. Do not submit private production content. Record its reference, capture point, time window, gaps, direction coverage, local asset, and external peer. Leave unestablished details blank. With the capture open, use Statistics, then Conversations. For a suitable packet, use Analyze, then Follow. A blank view does not prove anything about a case.

## Measurement limits
- Frame bytes include network overhead.
- TCP payload measures a different part of traffic.
- Unique application content requires interpretation.
- Retransmissions can repeat data; a partial capture can omit data.

No byte measure alone proves file identity, sensitivity, authorization, storage, or data loss. TCP acknowledgment does not prove that an application retained an object.