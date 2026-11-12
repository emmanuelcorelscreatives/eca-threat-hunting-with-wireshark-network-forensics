# Evidence worksheet

**Hypothesis:** A declared browser/form exchange may not fit the visible request body or response. An inconsistency warrants investigation, not a malicious verdict.

1. Record capture filename, collection point, time window, scoped host/IPs, whether both directions are visible, and any missing traffic. For this synthetic fixture, use the scenario scope in `DATA_DICTIONARY.md`; do not describe it as a real collection.
2. In Wireshark, try `http.request`, `http.user_agent`, `http.content_type`, and `urlencoded-form.key`. Record which filter or conversation pivot found each exchange. An empty view cannot recover missing packets and does not prove a header, form, or transfer was absent.
3. For each case, record actual frame references after opening practice.pcap. For port 51004 use tcp.stream == 3 and Packet Bytes: frame 22 is TCP-only and is not found by http.request. Distinguish visible header bytes from decoded HTTP fields:

| Client port | Request frame | Response frame or missing-reply limit | Method, Host, path, full User-Agent | Request Content-Type; Content-Encoding; visible body | Response status; Content-Type; Content-Encoding; visible body | Completeness and alternative |
|---|---|---|---|---|---|---|
| 51001 | | | | | | |
| 51002 | | | | | | |
| 51003 | | | | | | |
| 51004 | | | | | | |

4. Compare URL-encoded keys **and values** with available bytes; record only necessary synthetic values. For multipart, locate the declared boundary and each visible `Content-Disposition`. Treat a filename as supplied text, not proof of origin or contents. Check `Content-Encoding` before comparing declared type with bytes; do not equate an unreadable or incomplete body with an empty one.
5. Choose one exchange and write three separate sentences: **Observation** with capture and request/response frame citations; **significance** with a plausible benign explanation; **limit** stating what cannot be proved and the next useful application or endpoint context. If the advertised body or reply is unavailable, mark the comparison inconclusive. A User-Agent cannot identify a process or person; response headers cannot prove later actions.

Do not export or execute anything here. The next lesson addresses safe examination of a supplied inert object.