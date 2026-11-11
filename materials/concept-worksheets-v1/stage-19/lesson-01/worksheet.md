# Worksheet — Define What Data Loss Would Mean

> Large outbound connections can be routine; small ones can matter.
>
> What establishes data loss?
>
> Outbound traffic alone does not establish data loss.
>
> The practical answer is a question about loss with a clear scope and supporting evidence, not an outbound byte count.

## Synthetic exercise

The following fictional cards are teaching inputs, not a captured incident or observed packet results.

- **Card A — Alert:** An alert states that a workstation contacted an external service. It supplies no underlying packets, addresses, timing, or volume.
- **Card B — Capture status:** No authorized case capture, provenance record, collection window, capture point, or interface details are supplied.
- **Card C — Asset context:** An inventory note says a workstation role may access organizational data. Nothing maps that workstation to the alert, and no data-owner classification record is supplied.
- **Card D — Service context:** A service register says the service category is familiar and generally allowed for some teams. It does not identify an observed peer owner or approve this asset, dataset, purpose, or window.
- **Card E — Other evidence:** No endpoint, proxy, service, work-order, or owner-confirmation record is supplied. Protocol, content visibility, process, intent, transfer, and permission remain unknown.

## 1. Assess each dimension

| Dimension | Status | Card(s) | Exact observation and limitation |
|---|---|---|---|
| Asset and contact | ______ | ______ | ______________________________ |
| Destination or peer | ______ | ______ | ______________________________ |
| Channel and content visibility | ______ | ______ | ______________________________ |
| Data sensitivity | ______ | ______ | ______________________________ |
| Authorization context | ______ | ______ | ______________________________ |

## 2. Separate evidence from inference

Classify each statement using the controlled vocabulary.

1. Card A reports an alert allegation: __________
2. The alert device is the inventory workstation: __________
3. Sensitive data crossed a connection: __________
4. The service use was unauthorized: __________
5. The alert may justify further review: __________

## 3. Scope the case question

Write one question covering asset identity, peer contact, channel visibility, sensitivity, and specific authorization without assigning volume or a verdict.

____________________________________________________________________

____________________________________________________________________

## 4. Request the next evidence

Name one specific authorized record most likely to reduce the largest uncertainty. Explain why.

Record: _____________________________________________________________

Reason: _____________________________________________________________

## 5. Defensible statement

Write three sentences: one documented observation, one clearly labelled interpretation, and one limitation. Do not conclude that data loss occurred.

____________________________________________________________________

____________________________________________________________________