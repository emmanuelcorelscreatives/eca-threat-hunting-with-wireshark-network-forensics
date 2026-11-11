# Starting Skills Check — Answer Guide

> Draft reasoning key; separate review is required. It supplies no capture findings or fixed frame references.

## Expected reasoning

1. **TCP/IP:** Source and destination IP fields are network endpoints; ports and TCP flags help follow the conversation. SYN shows an attempt. SYN-ACK followed by ACK is the usual establishment exchange. None identifies a person, process, or later application behavior.

2. **DNS:** Record the query name/type, sender, and separately visible response. A query or answer does not prove a later connection. Missing traffic leaves capture scope, path, and whether a connection occurred unresolved.

3. **HTTP:** Record method/target and related response/status. A request alone does not prove delivery. If its response is outside the window, the response is unknown. A response proves neither identity, execution, nor authorization.

4. **TLS:** The network exchange and point where protected application content begins may be visible. TLS 1.3 application content remains unknown without working decryption material. Process identity requires authorized device information.

5. **Navigation:** The list supplies frame, displayed time, addresses, and protocol; selection exposes details and captured bytes. `tcp` changes only the displayed view and retains frame numbers. `http.request` seeks decoded HTTP requests; no matches means only that this view found none in that file.

## Reasoning-check key

The first statement is **S**upported; the other four are **U**nsupported. Stronger claims respectively require completed-handshake and application evidence, a separate later flow, wider or otherwise suitable visibility, and working decryption material. Person/process claims require authorized endpoint records.

## Checkable completion results

- **No-file route:** Status is Pending; capture metadata, observations, and frames stay blank. Five hypothetical answers, explicitly labelled Synthetic exercise rows, reasoning checks, and targeted review actions may be completed.
- **Authorized-file route:** Context precedes interpretation; three observations use actual frames; each hypothesis has an alternative and test; each unanswered question names needed evidence. Missing context is Unknown.
- Refreshers correspond only to missed reasoning, protocol, filter, or navigation skills. No score or compromise conclusion is required.