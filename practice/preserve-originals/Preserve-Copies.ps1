param(
 [Parameter(Mandatory=$true)][string]$SourcePath,
 [Parameter(Mandatory=$true)][string]$CaseRoot
)
$ErrorActionPreference = 'Stop'
function Read-ValidHash([string]$Path) {
 $value = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
 if ($value -notmatch '^[0-9A-Fa-f]{64}$') { throw 'STOP: no valid full SHA-256 digest.' }
 return $value.ToUpperInvariant()
}
$template = Join-Path $PSScriptRoot 'notes-template.md'
if (-not (Test-Path -LiteralPath $template -PathType Leaf)) { throw 'Missing notes-template.md.' }
if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) { throw 'Check the handoff path.' }
$receivedPath = (Resolve-Path -LiteralPath $SourcePath -ErrorAction Stop).ProviderPath
if ([IO.Path]::GetExtension($receivedPath) -ine '.pcapng') { throw 'Use a .pcapng input; do not relabel another format.' }
if (Test-Path -LiteralPath $CaseRoot) { throw 'Choose a new unique case directory.' }
$receivedHash = Read-ValidHash $receivedPath
New-Item -ItemType Directory -Path $CaseRoot -ErrorAction Stop | Out-Null
$casePath = (Resolve-Path -LiteralPath $CaseRoot).ProviderPath
foreach ($name in @('original','working','notes')) { New-Item -ItemType Directory -Path (Join-Path $casePath $name) -ErrorAction Stop | Out-Null }
$originalPath = Join-Path $casePath 'original\capture.pcapng'
$workingPath = Join-Path $casePath 'working\capture.pcapng'
$record = Join-Path $casePath 'notes\hash-checks.txt'
Copy-Item -LiteralPath $template -Destination (Join-Path $casePath 'notes\intake.md') -ErrorAction Stop
@(('Received path: '+$receivedPath),('Received SHA-256: '+$receivedHash)) | Set-Content -LiteralPath $record -Encoding UTF8
Copy-Item -LiteralPath $receivedPath -Destination $originalPath -ErrorAction Stop
$originalHash = Read-ValidHash $originalPath
$originalStatus = if ($receivedHash -ceq $originalHash) {'MATCH'} else {'MISMATCH'}
@(('Original path: '+$originalPath),('Original SHA-256: '+$originalHash),('Original vs received: '+$originalStatus)) | Add-Content -LiteralPath $record -Encoding UTF8
if ($originalStatus -ne 'MATCH') { throw 'STOP: received and original differ; retain the record.' }
Copy-Item -LiteralPath $originalPath -Destination $workingPath -ErrorAction Stop
$workingHash = Read-ValidHash $workingPath
$workingStatus = if ($originalHash -ceq $workingHash) {'MATCH'} else {'MISMATCH'}
@(('Working path: '+$workingPath),('Working SHA-256: '+$workingHash),('Working vs original: '+$workingStatus)) | Add-Content -LiteralPath $record -Encoding UTF8
if ($workingStatus -ne 'MATCH') { throw 'STOP: working and original differ; retain the record.' }
Get-Content -LiteralPath $record
