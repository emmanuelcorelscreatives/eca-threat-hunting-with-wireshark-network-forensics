# Setup — supplemental offline Protocol Hierarchy practice

This is a **separate, labelled synthetic Academy coursework capture**, not the unavailable case pack narrated in the unchanged lesson and not evidence about its historical case. Work only with an authorized offline copy. No live traffic or packets need be sent. If an instructor assigns the narrated case, obtain its authorized capture and inventory separately; do not transfer this fixture's percentages, frame numbers, roles, or findings to it.

## Obtain and identify the assembled kit

The assembled resources include `offline-builder.py`, `executed-fixture-spec.json`, its byte-identical alias `fixture-spec.json`, `practice.pcap`, `capture-context.csv`, `DATA_DICTIONARY.md`, this setup, `worksheet.md`, `answer-guide.md`, and the supplied `capture-info`, `all-frames`, `protocol-hierarchy`, `ip-conversations`, `tcp-conversations`, and `malformed` stdout/stderr logs. These files are delivered together in this supplemental lab. Stop and request the actual files if your delivery omits them; a Markdown description cannot substitute for the PCAP or builder. Read the CSV as scenario context, not ownership or authorization evidence.

The packaged builder's SHA-256 is `2e3f5f0f28b7f44cc7f0a84f8fec600ed2298db85a683619cb835c6be44ae98e`. The actual builder input and its alias each hash to `7cc31e96ddc6d78c4d75c2b3973b5c5d54c7d9aa509f728aad014861bab06e95`. The packaged PCAP is 1,008 bytes and hashes to `e10afad728c59c439fda842c80ef7b18f366c20922299ea3919b558f2ac09337`. A separate deterministic rebuild using the packaged builder and **`executed-fixture-spec.json`** produced identical PCAP bytes. Check what you actually obtained before using the checked key.

**Reconciliation with the earlier draft:** its `builder.py --spec fixture-spec.json --output practice.pcap` Windows command was a proposal, not a recorded execution. `builder.py` was not the packaged filename; `fixture-spec.json` is currently an identical alias, not the named executed input. Running that draft output path in the kit folder would risk overwriting the original because the actual builder uses `write_bytes`. The earlier `offline-dns-baseline.pcapng` was a proposed, distinct filename, **not** an output of this builder or a supplied conversion. Do not rename `.pcap` to `.pcapng` or report the proposed commands as run. Inspect and preserve any existing `practice/dns-baseline` source resource if one is separately required; a distinct mandatory baseline exercise remains on hold until its own resource and checks are supplied.

## Make a safe working copy; optional rebuild

The lecture uses Windows 11 / Wireshark 4.4.0. The independently recorded companion lab uses native Linux Qt Wireshark 4.4.0 on Ubuntu 24.04.5 LTS. The core packet and hierarchy tasks below are the same; this does not assert Windows execution. For an optional Windows reproduction, install Python 3 and TShark if authorized. The following PowerShell is a **proposed student procedure, not an executed Windows test**. Run it from a folder containing the assembled downloads. It creates a *new* directory, copies the original, and builds to a different new pathname. Stop on a missing path, mismatched hash, or failed build; never point `--output` at the packaged PCAP or another existing file.

```powershell
$Kit = (Get-Location).Path
$Builder = Join-Path $Kit 'offline-builder.py'
$Spec = Join-Path $Kit 'executed-fixture-spec.json'
$Alias = Join-Path $Kit 'fixture-spec.json'
$Original = Join-Path $Kit 'practice.pcap'
$Tshark = 'C:\Program Files\Wireshark\tshark.exe'
foreach ($p in @($Builder, $Spec, $Alias, $Original, $Tshark)) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw "Missing file: $p" }
}
$expectedSpec = '7cc31e96ddc6d78c4d75c2b3973b5c5d54c7d9aa509f728aad014861bab06e95'
$expectedCapture = 'e10afad728c59c439fda842c80ef7b18f366c20922299ea3919b558f2ac09337'
$expectedBuilder = '2e3f5f0f28b7f44cc7f0a84f8fec600ed2298db85a683619cb835c6be44ae98e'
if ((Get-FileHash -LiteralPath $Builder -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedBuilder) { throw 'Builder hash differs' }
foreach ($p in @($Spec, $Alias)) {
    if ((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedSpec) { throw "Spec hash differs: $p" }
}
if ((Get-FileHash -LiteralPath $Original -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedCapture) { throw 'Packaged capture hash differs' }
$Work = Join-Path $Kit ("student-check-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fffffff'))
New-Item -ItemType Directory -Path $Work -ErrorAction Stop | Out-Null
$Capture = Join-Path $Work 'working-copy.pcap'
$Rebuilt = Join-Path $Work 'rebuilt-practice.pcap'
Copy-Item -LiteralPath $Original -Destination $Capture -ErrorAction Stop
py -3 $Builder --spec $Spec --output $Rebuilt
if ($LASTEXITCODE -ne 0) { throw 'Offline rebuild failed' }
foreach ($p in @($Capture, $Rebuilt)) {
    if ((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedCapture) { throw "Capture hash differs: $p" }
}
```

You can practice with the verified working copy without rebuilding; rebuilding is an optional reproducibility check. Do not assume the proposed `py -3` invocation or TShark path works on every Windows installation. The supplied **executed Linux** logs establish `capinfos practice.pcap`, an unfiltered `tshark -r practice.pcap -q -z io,phs`, `-q -z conv,tcp`, `-q -z conv,ip`, an all-frames field extraction, and `-Y _ws.malformed -T fields -e frame.number`. They do not establish these optional PowerShell commands ran. Current additional decoder checks are recorded in `decoded-fields.execution.json` and `decoded-fields.stdout.csv`; current actual Linux native GUI records and exact images are listed in `native-execution.json` and `native-independent-approvals.json`.

## Read-only checks to perform on your copy

These are proposed Windows commands. The first two correspond to checks independently evidenced by the supplied Linux logs; the DNS flags/ID, ICMP types, and TCP flags below request **additional fields not present in those logs**. Confirm the field names in your installed TShark and investigate errors rather than filling gaps from the specification. The earlier draft's shorter DNS command did not show response flags or answers, and its shorter ICMP command did not show types.

```powershell
& $Tshark -r $Capture -T fields -e frame.number | Measure-Object -Line
& $Tshark -r $Capture -q -z io,phs
& $Tshark -r $Capture -T fields -e frame.number -e frame.time_utc -e frame.time_epoch -e frame.len -e frame.cap_len -e frame.protocols
& $Tshark -r $Capture -Y dns -T fields -e frame.number -e ip.src -e ip.dst -e dns.id -e dns.flags.response -e dns.qry.name -e dns.qry.type -e dns.a
& $Tshark -r $Capture -Y icmp -T fields -e frame.number -e ip.src -e ip.dst -e icmp.type -e icmp.ident -e icmp.seq
& $Tshark -r $Capture -Y tcp -T fields -e frame.number -e tcp.flags -e tcp.seq_raw -e tcp.ack_raw -e tcp.len -e tcp.payload
& $Tshark -r $Capture -Y http -T fields -e frame.number -e http.request.method -e http.request.uri -e http.host -e http.response.code -e http.file_data
```

Expect **11** frame-number lines from the independently executed Linux `capture-info` and `all-frames` evidence, but do not label the PowerShell pipeline executed until you run it. For timestamps, `frame.time_utc` produces text such as `Jan 16, 2025 12:00:00.000000000 UTC`; `frame.time_epoch` produces epoch seconds such as `1737028800.000000000`. Neither output is an ISO 8601 field. The pinned 4.4.0 field inventory found `frame.time_iso8601` **unsupported**; an older command proposing it was invalid and did not run.

In the Wireshark GUI, choose **File → Open** on the offline working copy; leave the **read filter** empty. If you must narrow loading, document the expression and excluded scope before interpreting totals. Clear the **display filter**, or explicitly choose and record statistics limited to displayed packets. Consult the CSV's capture point and UTC window, then follow `worksheet.md`. An empty filter cannot restore traffic outside a workstation-side collection point or the 0.420-second authored window. The recorded Linux native workflow opens the capture with no display filter, opens Protocol Hierarchy unfiltered, applies `icmp`, closes and reopens the hierarchy, checks actual frame 10 ICMP details, clears the filter, then closes and reopens the hierarchy again. See the checked answer guide and delivered native images. No Windows execution is claimed. Stop and document a discrepancy rather than copying Linux values into an unlike GUI scope.

The three TCP/80 frames are a handshake with `tcp.len=0` in the executed field output, not an HTTP request, response, transferred object, or file-content exercise. If a separately required source exercise calls for application transactions, an HTTP object, or file bytes, **retain it as an implementation hold** and obtain independently checked, application-bearing evidence. DNS names, a port number, and handshake frame bytes cannot satisfy it.

## Reproduce the recorded Linux companion workflow

Use Wireshark 4.4.0, TShark 4.4.0 and Python 3 as an ordinary user. From the extracted kit, run `sha256sum practice.pcap offline-builder.py executed-fixture-spec.json` and compare the hashes above. Create a new working folder with `mktemp -d`; copy `practice.pcap` there and pass a different, nonexistent output path to `python3 offline-builder.py --spec executed-fixture-spec.json --output /your/new/folder/rebuilt.pcap`. The builder overwrites an existing output: never use an original or existing file as output. Compare both copies using `sha256sum`. `rebuild-execution.json` records an actual byte-identical rebuild into a unique temporary path, not execution of your own commands.

Open your working copy with File → Open and leave any read filter empty. Check that the display filter is empty; open Statistics → Protocol Hierarchy. Record the bottom filter label and named row measures. Close it, apply `icmp`, and reopen it: confirm the bottom label now reads `Display filter: icmp`. Close it, select original frame 10 and open its Packet Details (double-click the row opens a separate packet window). Expand Internet Control Message Protocol; inspect Type, Identifier (BE), Sequence Number (BE), addresses and bytes. Bracketed response-frame links are generated analysis. Close the packet window, clear the display filter, and reopen the hierarchy; verify `No display filter.` and restored totals. Use the worksheet before reading the checked answers. Keep ownership, purpose and capture coverage separate from packet measurements.

The new decoder CSV was actually produced with `tshark -n -r practice.pcap -o ip.check_checksum:TRUE -o tcp.check_checksum:TRUE -o udp.check_checksum:TRUE -T fields` plus the exact `-e` field list recorded in `decoded-fields.execution.json`. Exit code and output hashes are recorded there. Run the same field list on your copy if you need independent confirmation; a prior receipt never asserts your machine executed it. The historical execution snapshot remains dated; `current-kit-inventory.json` identifies the current delivered bytes.
