# Registers scribed as a Windows service (plan phases 5 and 8). Run as Administrator from the folder
# that holds scribed.exe and scribe.toml. The MSI does this itself from phase 13.
#   .\install-service.ps1                 install and start, as NT SERVICE\scribed
#   .\install-service.ps1 -LocalSystem    install and start, as LocalSystem
#   .\install-service.ps1 -Remove         stop and remove
#
# NT SERVICE\scribed is the service's own virtual account: no password, no rights beyond what is
# granted here. It joins Performance Log Users (the ETW session), reads this folder and writes
# `data` and `logs` below it (add -Writable for a data_dir or log file elsewhere). Process paths
# come from ETW, so scribed needs no rights over other processes. With Npcap installed for
# Administrators only, packets aren't readable and flows come from ETW alone; use -LocalSystem then.
param(
    [switch]$Remove,
    [switch]$LocalSystem,
    [string[]]$Writable = @()
)
$ErrorActionPreference = 'Stop'
$name = 'scribed'
$account = "NT SERVICE\$name"
# Performance Log Users, by SID: the name depends on the system language.
$perfLogUsers = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-559').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]

if ($Remove) {
    Stop-Service -Name $name -ErrorAction SilentlyContinue
    & net.exe localgroup $perfLogUsers $account /delete 2>&1 | Out-Null
    sc.exe delete $name | Out-Null
    Write-Host "Removed service $name"
    return
}
$exe = Join-Path $PSScriptRoot 'scribed.exe'
if (-not (Test-Path $exe)) { throw "scribed.exe not found next to this script" }
New-Service -Name $name -DisplayName 'scribe outgoing connection tracker' `
    -BinaryPathName "`"$exe`" --service" -StartupType Automatic | Out-Null
sc.exe failure $name reset= 86400 actions= restart/5000/restart/5000/""/0 | Out-Null
# The service SID marks scribed's own objects (its pipe, files) even as LocalSystem.
sc.exe sidtype $name unrestricted | Out-Null

if (-not $LocalSystem) {
    sc.exe config $name obj= $account | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe config obj= $account failed ($LASTEXITCODE)" }
    & net.exe localgroup $perfLogUsers $account /add 2>&1 | Out-Null   # fails when already a member
    if (-not ((& net.exe localgroup $perfLogUsers) -match [regex]::Escape($account))) {
        throw "cannot add $account to $perfLogUsers"
    }
    # Read this folder (scribed.exe, scribe.toml); write data and logs.
    & icacls.exe $PSScriptRoot /grant "${account}:(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls $PSScriptRoot failed ($LASTEXITCODE)" }
    foreach ($dir in @('data', 'logs') + $Writable) {
        $path = if ([IO.Path]::IsPathRooted($dir)) { $dir } else { Join-Path $PSScriptRoot $dir }
        New-Item -ItemType Directory -Force -Path $path | Out-Null
        & icacls.exe $path /grant "${account}:(OI)(CI)M" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls $path failed ($LASTEXITCODE)" }
    }
}
Start-Service -Name $name
$as = if ($LocalSystem) { 'LocalSystem' } else { $account }
Write-Host "Installed and started service $name as $as"
