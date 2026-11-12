# Checked answers

Actual TShark4.4.0 decoding is delivered in rich-fields.tsv. The 20-frame rich capture has TCP stream0 in frames5–15 and stream1 in frames16–19. DNS frames1–2 are UDP stream0, frames3–4 UDP stream1, frame20 UDP stream2. These are file-local indexes, not identities or application intent.

Frame8 is HTTP GET with Host view.academy.test, TCP stream0. Frame10 is an HTTP response and has blank Host and Method request fields. Frame3 is UDP with UDP stream1 and no applicable TCP stream. Frames1 and2 both contain question name view.academy.test; only frame2 has DNS response name view.academy.test and A answer198.51.100.30.

Frame19 contains TLS ClientHello SNI tls.academy.test, TCP stream1. No ServerHello or completed TLS exchange is supplied. Its visible SNI is a captured client-provided name, not proof of authenticated server identity or an encrypted request.

Frame20 has one DNS question repeat.academy.test and two A answer records. dns.resp.name occurrence0 displays repeat.academy.test twice; occurrence1 and2 each display that same spelling once. dns.a occurrence0 displays198.51.100.50,198.51.100.51; occurrence1 displays198.51.100.50; occurrence2 displays198.51.100.51. Use Packet Details to establish which occurrence is selected; visually identical names do not mean one answer record. The response has no matching query in this synthetic excerpt; do not invent its earlier capture history.

`http.request` selects only frame8; clearing it restores20frames. A blank TLS cell in an unrelated packet is expected. A hidden frame is still in the file; an absent collection cannot be restored by clearing filters. Protocol decoding and capture visibility are further limits. A plausible cautious observation is that the captured client sent a particular SNI; a next check would be authorized additional handshake evidence. No fixture fact establishes compromise, ownership, user identity or production history. GUI screenshots are bounded demonstrations; actual CLI results are not represented as hidden GUI observations.

After Apply as Column for dns.a, frame8 has a blank added column because this HTTP request contains no decoded DNS A-address field. Returning to frame20 restores the DNS address values.
