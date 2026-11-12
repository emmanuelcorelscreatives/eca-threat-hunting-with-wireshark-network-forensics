# Learner worksheet — keep observations and inference separate

Work only with the supplied authorized offline fixture. Leave unsupported fields unresolved.

| Item | Your observation and exact source |
|---|---|
| PCAP name and SHA-256 | |
| Packet count; first/last frame time; selected display zone | |
| Collection point; observed span; missing portions | |
| Conversation endpoint pair and both packet directions | |
| Opening handshake references and visible service evidence | |
| One candidate authentication record ID, original message, outcome and account | |
| Record timestamp field and its actual basis | |
| Raw log endpoints and documented classroom alias relationship | |
| Historical asset-assignment evidence available or missing | |
| Measured clock error available or missing | |
| Inference supported by the combined records | |
| Routine administrative explanation and its source/limits | |
| Conflicting evidence or alternative candidates | |
| Unresolved operator identity, authorization and commands | |
| Narrow next evidence request | |

Negative controls: try a different server port (`tcp.port == 23`) and check whether an empty selection proves no access. Explain why it does not. Compare the `ssh` filter with `tcp.stream == 0`; explain which frames each view conceals. Do not create an attack label or a Windows 4624 event that is not present.

Write a short conclusion with three named parts: packet observation; authentication-record observation; supported inference and remaining limits. Include precise file/frame/record identifiers so another learner can repeat your join. Also explain how your result would weaken if address mapping, timestamp basis or excerpt coverage were missing.
