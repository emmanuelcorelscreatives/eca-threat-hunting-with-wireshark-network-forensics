# Answer Guide — Conceptual Rubric

Use this reasoning key after completing the worksheet. These are expected conceptual answers, not results from an executed capture.

## 1. Unloaded Wireshark

No packet finding can be reported. Entering `ssh` or `rdp` without a loaded capture supplies no evidence.

## 2. Intake assessment

None of the claimed network details can be corroborated because the source capture is not supplied. The sensor window omits 09:10–09:11 of the claimed period. A client-side span may not observe another route, and unknown direction completeness may hide how a conversation began. Missing traffic is not proof of failed access.

## 3. Conditional pivot

The address-and-port filter is reproducible only if an authorized capture is later obtained. It could locate candidate traffic matching those endpoints and TCP/22; it cannot prove SSH decoding, an accepted login, an account, commands, a person, or approval. `ssh` and `rdp` are not exhaustive because ports and decoding vary.

## 4. Separate claims

| Question | Expected status and next evidence |
|---|---|
| Network exchange | Open; request the source capture and document its collection limits. |
| Accepted account | Open; request destination-host authentication records. |
| Organizational approval | Open; request owner, maintenance, or access-approval context. |
| Post-access activity | Open; request available destination-host activity records. |

A host record might identify an accepted account, but not necessarily the person at the keyboard. Missing records do not prove that no login occurred.

## 5. Protocol reasoning

SSH protocol identification could support recognition of setup traffic. It would not expose the submitted account during ordinary protected authentication or prove success or commands.

`mstshash` is optional and client-supplied. It does not prove the authenticated account, successful authentication, desktop activity, identity, or permission.

## 6. Model uncertainty note

The fictional intake claims candidate TCP/22 traffic, but no source capture corroborates an exchange. Its stated sensor window is shorter than the claimed period, direction completeness is unknown, and collection is claimed at a client-side span. Login, activity, identity, and approval therefore remain open. Routine administration is an alternative requiring comparison with expected assets and timing. Request the authorized source capture, destination-host authentication and activity records, and owner or maintenance-approval context.