# Registers scribed as a Windows service (plan phases 5 and 8). Run as Administrator from the folder
# that holds scribed.exe and scribe.toml. The MSI (packaging\windows\scribe.wxs) and
# scripts\install\windows.ps1 run it. It also creates the local groups `scribe` (may read the API)
# and `scribe-admin` (may also control scribed) when they are missing; nothing removes them.
#   .\install-service.ps1                 install and start, as NT SERVICE\scribed
#   .\install-service.ps1 -LocalSystem    install and start, as LocalSystem
#   .\install-service.ps1 -Remove         stop and remove
#
# NT SERVICE\scribed is the service's own virtual account: no password, no rights beyond what is
# granted here. It joins Performance Log Users (to start the ETW session), may enable the three ETW
# providers scribed reads and read its session in real time (EventAccessControl, kept under
# HKLM\SYSTEM\CurrentControlSet\Control\WMI\Security), reads this folder and writes
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

# ETW access: the providers' and the session's GUIDs (crates/sensor-windows), and the rights.
$etw = @{
    '7dd42a49-5329-4832-8dfd-43d979153a88' = 0x80    # Kernel-Network: TRACELOG_GUID_ENABLE
    '1c95126e-7eea-49a9-a3fe-a378b03ddb4d' = 0x80    # DNS-Client
    '22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716' = 0x80    # Kernel-Process
    'defafa1b-0503-415d-80b4-7255907e23fe' = 0x400   # the scribe-etw session: TRACELOG_ACCESS_REALTIME
}
$wmiSecurity = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Security'

function Grant-Etw([string]$Sid) {
    if (-not ('ScribeEtw' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ScribeEtw {
    [DllImport("advapi32.dll")]
    public static extern uint EventAccessControl(ref Guid guid, uint operation, byte[] sid, uint rights, [MarshalAs(UnmanagedType.U1)] bool allow);
}
'@
    }
    $sidObj = New-Object Security.Principal.SecurityIdentifier $Sid
    $bytes = New-Object byte[] $sidObj.BinaryLength
    $sidObj.GetBinaryForm($bytes, 0)
    foreach ($guid in $etw.Keys) {
        $g = [Guid]$guid
        # 2 = EventSecurityAddDACL: one more entry on the current (or default) access list.
        $rc = [ScribeEtw]::EventAccessControl([ref]$g, 2, $bytes, [uint32]$etw[$guid], $true)
        if ($rc -ne 0) { throw "EventAccessControl $guid failed ($rc)" }
    }
}

# Takes the service's entries out of the ETW access lists again.
function Revoke-Etw([string]$Sid) {
    foreach ($guid in $etw.Keys) {
        $value = (Get-ItemProperty -Path $wmiSecurity -Name $guid -ErrorAction SilentlyContinue).$guid
        if (-not $value) { continue }
        $sd = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $value, 0
        $acl = $sd.DiscretionaryAcl
        for ($i = $acl.Count - 1; $i -ge 0; $i--) {
            if ($acl[$i].SecurityIdentifier -and $acl[$i].SecurityIdentifier.Value -eq $Sid) { $acl.RemoveAce($i) }
        }
        $out = New-Object byte[] $sd.BinaryLength
        $sd.GetBinaryForm($out, 0)
        Set-ItemProperty -Path $wmiSecurity -Name $guid -Value $out -Type Binary
    }
}

function Get-ServiceSid {
    try { (New-Object Security.Principal.NTAccount $account).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $null }
}

if ($Remove) {
    Stop-Service -Name $name -ErrorAction SilentlyContinue
    $sid = Get-ServiceSid
    if ($sid) { Revoke-Etw $sid }
    & net.exe localgroup $perfLogUsers $account /delete 2>&1 | Out-Null
    sc.exe delete $name | Out-Null
    Write-Host "Removed service $name"
    return
}
$exe = Join-Path $PSScriptRoot 'scribed.exe'
if (-not (Test-Path $exe)) { throw "scribed.exe not found next to this script" }

# The groups must exist before scribed creates its pipe (they are read into its access list).
$computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
foreach ($g in @(@('scribe', 'scribe API (read)'), @('scribe-admin', 'scribe API (control)'))) {
    $exists = try { [ADSI]::Exists("WinNT://$env:COMPUTERNAME/$($g[0]),group") } catch { $false }
    if (-not $exists) {
        $group = $computer.Create('Group', $g[0])
        $group.Put('Description', $g[1])
        $group.SetInfo()
    }
}
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
    $sid = Get-ServiceSid
    if (-not $sid) { throw "cannot find the SID of $account" }
    Grant-Etw $sid
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
