# Worksheet: one justified inert export

Hypothesis: a decoded HTTP response in this authorized working copy contains the supplied inert text. Alternatives include selecting the ordinary page or encountering an incomplete transfer. Complete one row in `artifact-register.csv`; use free text within quoted CSV cells where needed.

1. Record the capture identifier, original hash, authored window, observation point and gaps from your actual file and `fixture-manifest.json`. Open the working copy, then enter `http.request || http.response` in the display-filter bar. A filter neither restores missing traffic nor decrypts encrypted traffic.
2. Locate `/training/inert-training-object.txt`. Record the actual request frame, method, Host header and path. Locate the matching response; record its frame, status, declared content type, and decoded request/response pairing references. Expand HTTP in packet details as needed. A path or content type does not prove behavior.
3. Inspect the response's TCP reassembly context. Choose File → Export Objects → HTTP. Compare hostname, type, size and filename across both rows. Select only the inert text row, then choose Save, never Save All. Save into your isolated `exports` directory under an intentional text filename. Do not launch, install, preview or double-click it.
4. Record that row's Packet number. Close the exporter, choose Go → Go to Packet, and enter that number. Check the matching request/response and all body-carrying frames. The exporter Packet value is a starting point, not necessarily all body segments. Keep the export path separate from the capture path.
5. In Windows PowerShell run the following commands. Enter the full path of the file you actually just saved when prompted:

```powershell
$path = Read-Host 'Enter full path to the exported file'
Get-FileHash -LiteralPath $path -Algorithm SHA256
```

Record the displayed algorithm, full digest and exact path. Check that the path names the intended export. Hash the supplied `inert-training-object.txt` separately to compare actual bytes. If a file changes, hash it again; a previous digest identifies previous bytes. No path read or hash operation executes the text object.

6. Complete the register's delivery claim, unresolved execution status, alternatives, confidence limits and next action. Explain packet-supported reconstruction at the authored capture point separately from any endpoint saving or execution. If decoding/reconstruction fails, record the gap rather than guessing or forcing a hash match. State what endpoint telemetry would be needed for an execution claim. This prepares the next lesson, Project 3: The Suspicious Download.

Submit your completed CSV row and a short note on the source/working-copy hash comparison, selected row, pairing and reassembly context. Do not submit unknown payloads or private traffic.
