# Checked answer guide

The exact SHA-256 is `7b1bdeea772bea66c1c0c981a1c94c08b612ecdfa4898b017f6472dd51dd2671`. The actual supplied practice.pcap is 22 frames, 2,659 filesystem bytes, UTC 2025-02-20 10:00:00.000000–10:00:03.030000 (3.030000 s). It models an isolated synthetic link with both client/server directions present in the first three conversations. Addresses are documentation values, not attribution. See capture-controls.stdout.txt, http-fields.stdout.txt, http-details.stdout.txt and final-header-bytes.stdout.txt for actual local TShark4.4.0 evidence.

| Client port / stream | Request / response | Checked comparison |
|---|---|---|
| 51001 / 0 | 4 / 5 | POST /forms/basic, Host forms.academy.test, full User-Agent SyntheticBrowser/1. Request application/x-www-form-urlencoded, Content-Length 18; keys mode,item and values review,1. This request body has no trailing newline. Response 200 text/plain, length 9, accepted plus newline. |
| 51002 / 1 | 10 / 11 | Same method, Host, path and User-Agent. Request declares form encoding, length 15, but visible body is JSON text {"mode":"view"} with no trailing newline. The dissector reports that whole text as a form key and no value: a decoded key is not proof of semantically valid form pairs. Response 200 text/html, length 15, contains JSON {"status":"ok"} with no trailing newline. |
| 51003 / 2 | 16 / 17 | POST /forms/parts, same Host/User-Agent. Request multipart/form-data; boundary=academyB1, length 203. Packet bytes show boundary-separated mode and note parts and Content-Disposition, with filename="note.txt". The note contains INERT TEXT plus newline; the filename is supplied text. Response 200 text/plain, received plus newline, length 9. |
| 51004 / 3 | 22 / unavailable | Visible TCP payload contains request headers declaring 18 body bytes; no body or HTTP response is captured. Frame 22 is TCP-only in actual decoding. Do not invent a decoded method/header field or call the unrestricted session unanswered. |

No Content-Encoding field appears in the checked complete messages; none advertises compression. Compare actual visible bytes and completeness before interpreting the declarations. The first three modeled bodies are complete. For the last case the finite window ends at the header event; later transmission is unknown.

Example note: “In practice.pcap frames 10/11, a form declaration accompanies JSON request bytes, and a text/html response declaration accompanies JSON reply bytes.” “This deserves application-context review; an ordinary client/server configuration mistake could explain it.” “The packets do not identify a person or process, intent, execution, compromise or later actions; seek suitable endpoint/application records before strengthening the conclusion.”

Filters locate decoded fields, not ground truth. No filter match cannot prove absence. The stream view may help compare context, but cite packet frames. A protected capture lacking authorized secrets makes these fields unavailable. Preserve contradictory evidence and distinguish the separate authorized-own-capture homework from this supplied worked practice.
