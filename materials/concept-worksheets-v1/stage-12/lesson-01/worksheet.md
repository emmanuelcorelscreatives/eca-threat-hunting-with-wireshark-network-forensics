# Worksheet

Use only the synthetic premises in `setup.md`. Cite exercise record labels and enter `N/A—synthetic card` for source file and actual frames. Do not infer an actor, authorization, credential theft, compromise, or unshown traffic.

## A. Conversation analysis

| Field | KRB-01 | NTL-01 | LDP-01 |
|---|---|---|---|
| Records used | __________ | __________ | __________ |
| Operation or message role | __________ | __________ | __________ |
| Visible peers and directions | __________ | __________ | __________ |
| Request/response linkage | __________ | __________ | __________ |
| Relationship: observed, expected, or not yet established | __________ | __________ | __________ |
| Ordinary explanation that might fit | __________ | __________ | __________ |
| Visibility limit or unexplained point | __________ | __________ | __________ |
| Proportionate next action | __________ | __________ | __________ |

## B. Practical questions

1. Distinguish `AS-REQ`, `TGS-REQ`, and `AP-REQ`. Does K4 prove that S received an AP-REQ? Why?

   **Answer:** ________________________________________________

2. Map NTLM types 1, 2, and 3 to their labels. What does AUTHENTICATE establish, and what remains unsupported?

   **Answer:** ________________________________________________

3. Distinguish an LDAP bind from a search. What does L2 establish? What visibility caution follows L4?

   **Answer:** ________________________________________________

4. If a real exchange lacks a reply or a filter has no match, which four checks should precede a negative claim?

   **Answer:** ________________________________________________

5. Why can a peer relationship fit the map while compromise remains unproved?

   **Answer:** ________________________________________________

## Blank authorized-capture evidence template

Do not copy synthetic answers into this section.

- Source file identity: ____________________
- Capture point and time window: ____________________
- Both directions visible: ____________________
- Display filter: ____________________
- Actual frames: ____________________
- Decoded operation and field, such as `kerberos.msg_type` or `ntlmssp.messagetype`: ____________________
- Source, destination, and names actually decoded: ____________________
- Map match valid during the captured window: ____________________
- Request/response or LDAP session/message-ID linkage: ____________________
- Ordinary explanation: ____________________
- Visibility limit: ____________________
- Next action: ____________________