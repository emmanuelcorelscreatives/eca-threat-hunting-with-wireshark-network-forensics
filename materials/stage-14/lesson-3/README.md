# Controlled TLS session: complete supplemental Academy practice

This separate Academy exercise supplies real encrypted TLS traffic and its matching disposable session key log. The saved lecture remains a no-file demonstration and does not claim these results. These files are synthetic Academy-owned teaching materials, not a historical incident or a learner's own capture.

Use Wireshark 4.4 on Windows 11 (English/light theme) to follow the lecture. Actual included native screenshots were recorded on Ubuntu 24.04 with Wireshark 4.4.0; they do not certify Windows actions. TShark evidence was independently executed locally. No network connection or live capture is needed.

## Download and restrict

Download the complete lesson ZIP from the Academy lesson resources and extract into a case directory restricted to authorized lab analysts. Keep the original unchanged and create a working copy of `controlled-tls-session.pcapng`. `controlled-tls-session.keys` contains only disposable secrets generated for this public synthetic lab; it is intentionally distributed for this exercise. The filename and public distribution are not technical access controls. In real casework, use actual restricted storage and never publish real keys. Apply the same restricted handling to readable derivatives and screenshots. Do not copy secret values into the worksheet.

Read `case-note.json`, check capture and key-log SHA256 using `verification.json`, and record origin and authorization. PowerShell: `Get-FileHash .\controlled-tls-session.pcapng -Algorithm SHA256`. No production secrets, private certificates or external service credentials are supplied.

## Same-session test

1. Create a clean Wireshark profile. Open Edit → Preferences → Protocols → TLS. Clear `(Pre)-Master-Secret log filename`, apply, and confirm it is empty. Open the working capture through File → Open.
2. Enter `tls`. Record frame, time, endpoints, stream and visible TLS details. The designated client is 192.0.2.10:54000, server 198.51.100.20:443, stream 0. Capture point is a synthetic serialized Ethernet transport, not a real collector. Inspect Analyze → Follow → TLS Stream if available; record the actual before view without assuming plaintext exists.
3. Read the key-log origin in the case note. In TLS preferences, choose the supplied matching `.keys` file from the case directory without displaying values. Apply. Accepting a preference is not decryption proof.
4. Return to stream 0. Try `tls and (http or http2)`. Select the named request and response, expand their decoded HTTP details, and record method, URI, response status and original frame references. Use `http` as a broader application pivot if necessary, returning to endpoints and stream to confirm identity. Follow → TLS Stream again and compare both directions with the before view.
5. Complete `comparison-worksheet.md` before consulting `answer-guide.md`. A label alone is weaker evidence than the expected GET and 200 response in the same session.
6. Clear the display filter and recheck the full 15-frame scope and UTC window. Check TLS preferences, clear the case key-log filename, apply and confirm the field is empty. Clearing that field does not delete evidence, decrypted exports, debug logs or pcapng secrets blocks. Record and restrict derivatives under the case procedure.

An empty result alone cannot diagnose the secret, capture or decoder. Stop if authorization or match is unclear. Do not try random production keys. These packets cannot establish user identity, process execution, intent, or another action.

## Included evidence

`verification.json` binds actual executed argv, outputs and hashes. `before-http.txt` is empty. `after-http.txt` contains one matching GET and one 200 response. Follow outputs show the actual before/after text. Native screenshots show narrow actual Linux packet-list views; they do not certify expanded detail, preference selection or a full GUI walkthrough. `generation-receipt.json` describes genuine OpenSSL TLS1.2 encryption using Python SSL memory BIOs, wrapped in Academy-authored synthetic TCP transport. No live network collector is claimed. No decryption secrets block is embedded in this pcapng. Raw keys are separate.

To reproduce the read-only checks with tools on PATH, run `python verify.py` from this extracted directory (Python 3 required). The script uses only local supplied files and writes verification outputs; preserve originals elsewhere before running. The generation code is supplied as `build.py` for inspection, but it is not a turnkey student capture builder: it deliberately refuses to overwrite an existing capture and expects its original maintenance directory layout. Use the ready-made lab files for this exercise.
