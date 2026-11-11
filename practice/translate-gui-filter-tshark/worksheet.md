# Selection-comparison worksheet

**Hypothesis:** With one unchanged file, no Wireshark read filter and the identical validated display filter, Wireshark and TShark should select the same original frame numbers. Test this; do not assume it.

- Authorized working-copy path: ______  Local file identity and method: ______
- Wireshark filename confirmed: ______  Read-filter field empty? ______
- Wireshark version: ______  TShark version: ______
- Exact validated display-filter expression in both tools: ______
- Wireshark total **Packets**: ______  **Displayed**: ______
- Ordered Wireshark **No.** values: ______
- TShark summary-line count: ______  Ordered TShark frame numbers: ______
- Same count **and** same ordered numbers? ______
- Shared frame number, *only if observed in both*: ______  Wireshark protocol details and visible neighboring packets: ______
- File identity after comparison: ______  Unchanged? ______

If results differ, check both paths, Wireshark’s opening read filter, expressions character by character, and relevant installed-tool analysis settings. Reopen the intended file without a read filter and compare again; record what remains unresolved: ______. Different summary columns alone are not different selections. If there is no shared number, leave the packet-reference field blank. If there are zero matches, report zero *in this file under this filter*, not absence from the environment.

Captured-frame evidence: ______  Alternative explanation or missing telemetry: ______  Confidence limit: ______  Next useful action: ______. Do the packet details answer your question, or is a better observation point or time window needed? ______