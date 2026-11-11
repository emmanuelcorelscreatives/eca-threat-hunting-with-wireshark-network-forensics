# Read TCP Setup, Transfer and Teardown

**Supplemental synthetic practice.** This is not the unavailable case mentioned in the saved lecture. Use only [the supplied tcp-http-download.pcap](../captures/tcp-http-download.pcap) and the declared synthetic specification. No live collection is needed.

## Learner worksheet

1. Locate SYN, SYN/ACK and the next ACK. Record both endpoints and ports.
2. Record the raw initial sequence numbers and explain why the acknowledgment advances after SYN. Distinguish raw from Wireshark relative sequence display.
3. Find the request and response payload frames and the FIN/ACK sequence. What packet references support bidirectional visibility in this authored exchange?
4. Does a completed TCP exchange establish a user, trusted purpose or file execution?

| Observation and exact frame reference | Tentative explanation | Alternative or unknown | Evidence limit / next authorized record |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

Record display-filter state: __________

Record display time zone and source file hash: __________

Bounded conclusion: __________

## Answer key — read after completing the worksheet

The TCP conversation is 192.0.2.10:54000 to198.51.100.20:80. Frames 3/4/5 provide SYN, SYN/ACK and ACK. Raw initial sequence numbers are 1000 and 9000; the SYN consumes one sequence number, so the acknowledged next values are 1001 and 9001. Relative UI sequence display can show a different origin. Request bytes are in 6, response bytes in 8. Frame 10 is server FIN/ACK,11 acknowledges it,12 is client FIN/ACK and 13 is the final server ACK. Both packet directions exist in this designed exchange; this does not establish real collector coverage, user identity, legitimate purpose or execution.

The checks refer to the exact downloadable fixture, independently decoded with TShark. See [its verification receipt](../verification/tcp-http-download.json). These facts must not be presented as an observed result of the saved lecture's missing case.
