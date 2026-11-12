# Setup and preservation

Use Wireshark Desktop with HTTP Export Objects and Windows PowerShell (`Get-FileHash`). Python 3 is optional for an offline rebuild; TShark is optional for the maintainer checks below. The delivered `practice.pcap`, `fixture-spec.json`, `offline-builder.py` and `inert-training-object.txt` are ready to use; no missing builder or draft alias is required. Extract the entire kit into a dedicated analysis directory. Do not use private traffic, credentials or unknown payloads.

Read `fixture-manifest.json` before opening the capture. It explicitly labels the documentation-only link and UTC window as authored synthetic scope, not measured collection coverage. The capture contains 23 frames and is 2,023 filesystem bytes. Its SHA-256 is `fcbb8543fcfad88514a64ee5a20d46dc5adae73fc3c3cc826b6685ac9903a198`. Preserve `practice.pcap` as your original. In PowerShell, from the extracted kit directory:

```powershell
Get-FileHash -LiteralPath .\practice.pcap -Algorithm SHA256
Copy-Item -LiteralPath .\practice.pcap -Destination .\working.pcap -ErrorAction Stop
New-Item -ItemType Directory -Path .\exports -ErrorAction Stop
```

Use a fresh workspace where `working.pcap` and `exports` do not already exist; check the copy's hash against the original. Open `working.pcap` in Wireshark using File → Open. Keep your export path distinct from both capture paths.

To rebuild without network access, use a new output name:

```text
python offline-builder.py --spec fixture-spec.json --output rebuilt-practice.pcap
```

The builder validates explicit synthetic input, documentation addresses and ordered timestamps before writing; it refuses an existing output. Hash the result and compare with the supplied capture hash. `builder-execution.json` records an actual byte-identical rebuild, refusal of an existing output, and three invalid-input rejections. The builder does not establish GUI results.

Optional maintainer commands, run from this kit directory with a fresh `verification-export` destination:

```text
tshark -2 -r practice.pcap -Y "http.request || http.response" -T fields -E header=y -e frame.number -e http.request.method -e http.host -e http.request.uri -e http.response.code -e http.content_type -e http.request_in -e http.response_in
tshark -r practice.pcap --export-objects "http,verification-export"
```

The second command exports both objects and is an isolated maintainer check, not the learner's single-row task. The retained `http-fields.stdout.txt` and `maintainer-http-export.stdout.txt` are actual executions; the execution record includes the exact original absolute destination. No `proposed/` path is a current instruction.

Actual GUI evidence was collected with native Linux Wireshark 4.4.0 on Ubuntu 24.04. The separate hash receipt and screenshot came from real Windows 11 Enterprise LTSC Evaluation build 26100, Windows PowerShell 5.1. The Windows check read the same saved export through a redirected analysis share; this is not an endpoint-recovered file. Learners use their own real export path. These checks do not certify all operating system versions.
