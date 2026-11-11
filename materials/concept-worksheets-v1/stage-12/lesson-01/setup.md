# Setup

**Draft supplemental material—synthetic exercise.** No PCAP, case environment map, packet frames, addresses, timestamps, accounts, or software output are supplied. The cards below are teaching premises, not captured incidents, Wireshark results, or case findings. They cannot identify a machine or person.

Download and open `setup.md`, `worksheet.md`, and `answer-guide.md` in any Markdown reader. No Wireshark, Python, credentials, or network access is required. Complete the worksheet before opening the guide. For optional real-evidence practice, only an authorized capture and its contemporaneous address-to-role map are suitable; neither is required or included.

## Reference

First look: `kerberos or ntlmssp or ldap`. Focus filters: `kerberos`, `ntlmssp`, and `ldap`. A display filter limits the view without deleting packets. An empty view proves nothing; check capture point, time window, direction, and decoding.

## Synthetic role map

| Token | Role and mapped purpose |
|---|---|
| W | Workstation; mapped to use D for domain authentication and S for file service |
| D | Domain controller/directory server; manages domain accounts |
| S | File-service server |
| C | Service client; mapped to query D |

This map has no address or validity window, so it cannot name a real asset.

## Synthetic conversation cards

Record labels are exercise IDs, never packet or frame numbers.

| Record | Conversation | Teaching premise |
|---|---|---|
| K1 | KRB-01 | AS-REQ, W → D |
| K2 | KRB-01 | AS-REP, D → W |
| K3 | KRB-01 | TGS-REQ, W → D |
| K4 | KRB-01 | TGS reply, D → W; no AP-REQ supplied |
| N1 | NTL-01 | NEGOTIATE, type 1, W → S |
| N2 | NTL-01 | CHALLENGE, type 2, S → W |
| N3 | NTL-01 | AUTHENTICATE, type 3, W → S |
| N4 | NTL-01 | File-service context; reason for NTLM not supplied |
| L1 | LDP-01 | BindRequest, C → D |
| L2 | LDP-01 | Corresponding same-session BindResponse described as success, D → C |
| L3 | LDP-01 | SearchRequest, C → D |
| L4 | LDP-01 | StartTLS follows; later directory content not supplied |

## Data dictionary

`Record` is a unique exercise label. `Conversation` groups related premises. `Teaching premise` contains only the stated operation, direction, context, or visibility. **Not supplied** is a null value and must not be inferred. Control totals are 12 records, three conversations, and four records per conversation.