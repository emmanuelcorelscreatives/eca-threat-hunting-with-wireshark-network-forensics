$ErrorActionPreference = 'Stop'
Start-Transcript -Path '\\tsclient\agentic\s10l4-export\windows-hash-transcript.txt'
$PSVersionTable | Format-List
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List
$path = Read-Host 'Enter full path to the exported file'
$result = Get-FileHash -LiteralPath $path -Algorithm SHA256
$result | Format-List Algorithm,Hash,Path
[ordered]@{ executedAt=(Get-Date).ToUniversalTime().ToString('o'); algorithm=$result.Algorithm; hash=$result.Hash; path=$result.Path; bytes=(Get-Item -LiteralPath $path).Length; platform=[Environment]::OSVersion.VersionString; powershell=$PSVersionTable.PSVersion.ToString() } | ConvertTo-Json | Set-Content -LiteralPath '\\tsclient\agentic\s10l4-export\windows-hash-receipt.json'
Stop-Transcript
Read-Host 'Recorded; press Enter only to close'
