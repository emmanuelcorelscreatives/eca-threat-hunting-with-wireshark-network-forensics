# Claim Review Answer Guide

## Use of this guide

These are acceptable responses to the synthetic, conditional exercise—not case findings. Because no capture or related records were supplied, an answer must not claim that a connection actually occurred.

## Task 1 — Expected reasoning

| Claim | Acceptable label and reasoning |
|---|---|
| Connection presence | **Fact only conditionally:** if an authorized capture shows it, the narrow fact is that an encrypted connection appeared in recorded traffic during the observed window. State capture point, window, packet completeness, and display-filter limits. An alternative to the observation itself is **not applicable**; if a matching capture were supplied, inspecting it and its collection and viewing scope would be the minimum authorized check. No capture was supplied for this exercise. |
| Investigative relevance | **Inference.** Timing and peer may warrant examination, but the connection alone does not establish relevance. Approved software activity is a credible alternative. A time-matched process-to-network link to activity independently tied to the case could strengthen relevance; approved activity explaining the same host, time, and peer could weaken it. Seek the narrow authorized record capable of testing the interpretation, if available. Neither result proves intent. |
| Proposed purpose or intent | **Inference, unsupported by the connection alone.** A proposed purpose needs its own basis; actor intent remains unknown. Approved activity is a credible alternative. Seek authorized, time-matched activity records linking the process and session to the proposed activity, if available. Even a match would not prove intent. |
| Starting process | **Unknown.** No process-to-network link was supplied, and packet addresses alone cannot identify the starting process. No particular process is proposed, so **not applicable** is acceptable as an alternative to a proposed process. Seek the smallest time-matched process-to-network record linking a process on the relevant host to this connection, if available. Check address mapping and clock alignment. A process name found elsewhere on the host is insufficient. |
| Transferred content | **Unknown.** An encrypted connection alone does not reveal its application data; approved software traffic is a plausible alternative. Seek authorized access to the matching session’s contents or another record identifying the data, if available. Connection length, total bytes, and another volume measurement do not identify the content. |
| Sensitivity of any data | **Unknown.** Identifying content would not automatically establish that it was sensitive; routine or nonsensitive data is an alternative. If data is identified, seek an authorized classification or data-owner record for that data, if available. Traffic volume cannot establish sensitivity. |
| Whether data was stolen | **Unknown.** Even identifying sensitive data would not by itself establish theft; an authorized transfer or no transfer is an alternative. Seek narrowly matched, authorized evidence of whether identified data left through this connection and whether that transfer was unauthorized, if available. Content identification or traffic volume alone cannot establish theft. |

The original sentence fails because strong support for connection presence cannot supply missing support for process, content, sensitivity, theft, or intent.

## Task 2 — Expected limits

The six scenario-specific fields should say **not supplied**, including whether a display filter was used. For its general effect, state that a display filter hides packets without deleting them. An absence claim must remain bounded. An acceptable rewrite is:

> No matching packet appeared in the view examined; whether related activity occurred outside that view remains unknown.

Cross-source order is **provisional** until clock alignment is checked. A packet timestamp alone does not establish that another system’s clock matches it.

## Task 3 — Checkable confidence answer

A complete response should include:

- **Raise confidence:** if an authorized, time-matched process-to-network record links the connection on the relevant host to a process that available case records independently tie to the investigated activity, relevance may strengthen. Check address mapping and clock alignment; the link alone does not establish content or intent.
- **Lower confidence:** if approved activity explains the peer for the same host and time, suspicion weakens. That explanation does not establish harmlessness or intent.
- **Remain unknown:** content remains unknown after a process match; purpose or intent may remain unknown even if the process or content is identified.
- **Requester:** a generic role authorized to request records through the case process, or **not supplied**, is acceptable. No case-assigned requester or specific person was provided.

Do not use a precise confidence percentage. The answer should name its support, limits, strongest plausible alternative, and a test capable of changing confidence in either direction.