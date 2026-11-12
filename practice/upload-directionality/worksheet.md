# Worksheet — what traveled outward?

For each separate capture record asset, peer, window, collection point, both directions, and coverage limits. A filter cannot repair missing collection. The synthetic observation point is authored; the TLS capture was made on the author's loopback interface. Neither proves production coverage.

1. Record TCP initiator, both directional packet/byte totals, start, duration, and nearby timing. Distinguish packet bytes from application bytes.
2. For HTTP apply `http.request.method in {"POST", "PUT"}`; inspect request, body and response, then Follow TCP Stream and return to original timing. Does Content-Length prove capture completeness or server retention?
3. For FTP use `ftp.request.command == "STOR"`; correlate PORT address/port, STOR and RETR, data-connection SYNs, payload direction and timing. Does server initiation make the server the uploader?
4. For TLS decode server55451 as TLS. Identify handshake and encrypted application-data records in both directions. Record what packet-only evidence supports before reading the separate application receipt. What additional claim does that receipt support, and what remains unknown? Explain why neither TLS nor SFTP over SSH reveals protected file operations or filenames without authorized supporting visibility. No SFTP capture is supplied or claimed.
5. Use I/O Graphs with a stated interval/filter/unit to compare each capture's activity with nearby packets in that same capture. Do not compare the captures as one window. Graph bytes do not identify encrypted file bytes.

| Case | Initiator | Payload direction/visible operation | Frame or record evidence | Alternative explanation | Unknown and next evidence request |
|---|---|---|---|---|---|
| HTTP | | | | | |
| FTP STOR | | | | | |
| FTP RETR | | | | | |
| TLS packet-only, then receipt | | | | | |

Write a bounded finding and separately label your hypothesis. Test approved work, backup or synchronization against owner destination/schedule records. Request an authorized endpoint/proxy operation record for protected content, owner authorization/sensitivity records for a loss claim, or another capture point for incomplete coverage. Never treat direction totals, method names, response status or encryption as proof of exfiltration. Optional follow-on: repeat only on an independently authorized own capture; that learner task has not been performed here.
