# Authorized-Capture Setup

> Draft shared prerequisite; separate review is required.

## Inputs

- An isolated training host with Wireshark. `tshark` is optional for instructor fixture verification.
- `worksheet.md` and `answer-guide.md`.
- Optional instructor-supplied, authorized pcap or pcapng. No diagnostic capture currently accompanies this lesson.
- Optional DNS-only supplement from the verified repository at `practice/dns-baseline/README.md` and its six-packet synthetic fixture. It is not the diagnostic capture.

## Procedure

1. Exclude workplace and live-network traffic. If no diagnostic file exists, use the no-file route.
2. When an authorized file exists, use Wireshark’s File → Open to select it.
3. Before interpretation, record file identity, intended time window, capture point, and known gaps from supplied context. Mark missing context Unknown.
4. Select a real packet row to inspect details and captured bytes.
5. Apply `tcp`, then replace it with `http.request`. Filters change the displayed view, not file contents.
6. Keep the optional DNS supplement separate and make no compromise or later-connection claim from it.