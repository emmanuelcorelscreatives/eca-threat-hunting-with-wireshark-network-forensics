# Worksheet

## Synthetic evidence cards

All cards below are synthetic exercises.

| ID | Supplied card |
|---|---|
| RS-01 | `C1↔S1`; unspecified viewpoint, brief window; TCP destination port 3389; undecoded; no setup detail. |
| RS-02 | `C2→S2`; opening visible, return direction missing; TCP 3389; decoded RDP; client X.224 Connection Request only. |
| RS-03 | `C3↔S3`; opening and both directions visible; TCP 3389 has a client X.224 Connection Request and server X.224 Connection Confirm; related UDP exists between the peers. |
| RS-04 | `C4↔S4`; late-starting short window; TCP destination port 22; undecoded; no identification strings. |
| RS-05 | `C5↔S5`; opening and both directions visible; nonstandard TCP port; each peer sends an identification string beginning `SSH-2.0-`. |
| RS-06 | `C6↔S6`; capture starts after opening; TCP 22 decoded as SSH; only later protected traffic is represented. |
| RS-07 | `C7↔S7`; both directions visible; TCP 5985 decoded as HTTP; request path has the default `wsman` URL prefix and a reply; SOAP management content is unavailable. |
| RS-08 | `C8↔S8`; both directions visible; TCP 5986 carries HTTPS; no visible `wsman`, SOAP, or management detail. |
| RS-09 | `C9→S9`; nonstandard TCP port; setup and return direction missing; undecoded opaque traffic; supplied context merely nominates WinRM. |

## Classification

For every card, enter one tier, a bounded service assessment, one limitation, one plausible routine explanation, and one focused record that could test it.

| ID | Tier; service and confidence | Coverage or unsupported claims | Routine explanation; testing record |
|---|---|---|---|
| RS-01 |  |  |  |
| RS-02 |  |  |  |
| RS-03 |  |  |  |
| RS-04 |  |  |  |
| RS-05 |  |  |  |
| RS-06 |  |  |  |
| RS-07 |  |  |  |
| RS-08 |  |  |  |
| RS-09 |  |  |  |

## Short responses

1. Before filtering a real authorized capture, which four context items should be recorded?  
   **Answer:** ______________________________________________
2. What does `rdp || ssh` show, and what does it not prove?  
   **Answer:** ______________________________________________
3. Why check UDP between an RDP candidate's peers?  
   **Answer:** ______________________________________________
4. Why are two `SSH-2.0-` strings stronger than port 22?  
   **Answer:** ______________________________________________
5. Would Decode As prove RS-09 is WinRM? Explain.  
   **Answer:** ______________________________________________
6. What does RS-07 support, and what remains unproved?  
   **Answer:** ______________________________________________