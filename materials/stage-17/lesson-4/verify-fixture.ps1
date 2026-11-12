param([string]$TShark = "C:\Program Files\Wireshark\tshark.exe")
$ErrorActionPreference = "Stop"
& py -3 "$PSScriptRoot\verify_fixture.py" --tshark $TShark
if ($LASTEXITCODE -ne 0) { throw "Fixture verification failed with exit $LASTEXITCODE" }
