# Registers scribed as a Windows service (plan phase 5). Run as Administrator from the folder that
# holds scribed.exe and scribe.toml. The MSI does this itself from phase 13.
#   .\install-service.ps1            install and start
#   .\install-service.ps1 -Remove    stop and remove
param([switch]$Remove)
$ErrorActionPreference = 'Stop'
$name = 'scribed'
if ($Remove) {
    Stop-Service -Name $name -ErrorAction SilentlyContinue
    sc.exe delete $name | Out-Null
    Write-Host "Removed service $name"
    return
}
$exe = Join-Path $PSScriptRoot 'scribed.exe'
if (-not (Test-Path $exe)) { throw "scribed.exe not found next to this script" }
New-Service -Name $name -DisplayName 'scribe outgoing connection tracker' `
    -BinaryPathName "`"$exe`" --service" -StartupType Automatic | Out-Null
sc.exe failure $name reset= 86400 actions= restart/5000/restart/5000/""/0 | Out-Null
Start-Service -Name $name
Write-Host "Installed and started service $name"
