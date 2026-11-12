# Preserve originals and work on copies

The saved lesson supplies no historical case PCAP. For that demonstration select an authorized received file and its handoff; if unavailable, stop at path selection. The separately supplied Academy synthetic fixture is a 48-byte, zero-packet pcapng for practicing file handling only. It supplies no traffic findings. Do not substitute it for an unavailable case.

Extract this entire kit into a local folder. This separate supplemental lab was actually tested with PowerShell 7.6.9 on Linux. The saved lecture demonstrates Windows 11, Windows PowerShell 5.1 and Wireshark 4.4.0 but explicitly does not require those versions. Windows 5.1 execution is not asserted; use the tested PowerShell 7 route for this downloadable lab. Set `$lab` to that folder before choosing either branch. Keep notes-template.md beside Preserve-Copies.ps1.

```powershell
$ErrorActionPreference = 'Stop'
$lab = (Resolve-Path -LiteralPath '/REPLACE/ENTIRE/KIT-FOLDER' -ErrorAction Stop).ProviderPath
# Isolated optional Academy practice:
$source = Join-Path $lab 'synthetic-handling-only.pcapng'
$case = Join-Path ([IO.Path]::GetTempPath()) ('AcademyCopies-' + [guid]::NewGuid().ToString('N'))
& (Join-Path $lab 'Preserve-Copies.ps1') -SourcePath $source -CaseRoot $case
```

For an authorized case replace the entire `$source` path and choose a new policy-approved `$case` path instead of TEMP. Confirm the source against the handoff. Do not relabel another format .pcapng. The script hashes received bytes before copying, copies into original/capture.pcapng and verifies its hash, then copies that verified original into working/capture.pcapng and verifies again. It validates full digests and stops on errors or mismatch. It refuses an existing case directory. It never deletes the received file, sanitizes data or creates a derivative. If it fails, retain the partial case and record; investigate paths and copy completion, and use a new directory after resolving the problem.

Independently run Get-FileHash -LiteralPath <full path> -Algorithm SHA256 against received, original and working. Compare all 64 characters and record actual results. Fill notes/intake.md using the handoff and observed checks. Supplier, recipient and actual arrival time with time zone must come from the handoff; unknown stays unknown. The synthetic-handoff.json is explicitly a practice identity record; fill your own local receipt time and path.

After verified matches, optionally use Wireshark File > Open to select the full working path, check that it is under working, and record the path only if actually opened. No shipped evidence claims a GUI open. The zero-packet fixture is intentionally empty. Do not Save As over original; control access under workplace rules. A folder name is not write protection. Hash agreement supports byte equality at the check time, not collector identity, completeness, both directions, authenticity, suspiciousness or packet meaning. A later changed derivative requires its own path and hash, preserved parent path and hash, change description, operator and time; none is created here.
