<#
.SYNOPSIS
  Installs or removes scribed as a Windows service by hand, without the MSI
  (scripts\build\windows-msi.ps1); refused while the MSI is installed. Run from an Administrator
  PowerShell.

.DESCRIPTION
  scripts\install\windows.ps1 install [-From <dir>] [-Dir <dir>] [-LocalSystem]
  scripts\install\windows.ps1 uninstall [-Dir <dir>] [-Purge]

  install    scribed.exe, scribe.exe, the service and notify scripts to -Dir (default
             C:\Program Files\scribe), scribe.toml there (kept if it is there; data and logs go to
             data\ and logs\ next to it), the local groups `scribe` (may read the API) and
             `scribe-admin` (may also control scribed), -Dir on the system PATH, then the service
             through install-service.ps1: as NT SERVICE\scribed (-LocalSystem: as LocalSystem),
             started. Run it again to upgrade.
  uninstall  removes the service (and its ETW and group grants), the programs, the scripts and the
             PATH entry; keeps scribe.toml, data, logs and the groups unless -Purge.
  -From      the folder with scribed.exe and scribe.exe: an extracted release archive (the default
             when this script sits in one), else this repository's release build
             (target\x86_64-pc-windows-msvc\release, target\release), which must be of this
             checkout (rebuild it otherwise).

  Add people to the groups with `net localgroup scribe <name> /add` (they sign in again to get it).
  Npcap (optional, for SNI and URLs) is installed separately from npcap.com.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory)]
    [ValidateSet('install', 'uninstall')]
    [string]$Action,
    [string]$From,
    [string]$Dir = (Join-Path $env:ProgramFiles 'scribe'),
    [switch]$LocalSystem,
    [switch]$Purge
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Here = $PSScriptRoot
$Root = Resolve-Path (Join-Path $Here '..\..') -ErrorAction SilentlyContinue
function Say([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run this from an Administrator PowerShell'
}

# Local groups through ADSI (works in Windows PowerShell 5.1 and PowerShell 7).
$computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
function Test-Group([string]$Name) {
    try { [ADSI]::Exists("WinNT://$env:COMPUTERNAME/$Name,group") } catch { $false }
}

function Find-Bins {
    if ($From) {
        if (-not (Test-Path (Join-Path $From 'scribed.exe')) -or -not (Test-Path (Join-Path $From 'scribe.exe'))) {
            throw "no scribed.exe and scribe.exe in $From"
        }
        return (Resolve-Path $From).Path
    }
    $candidates = @($Here)
    if ($Root) { $candidates += (Join-Path $Root 'target\x86_64-pc-windows-msvc\release'), (Join-Path $Root 'target\release') }
    foreach ($c in $candidates) {
        if ((Test-Path (Join-Path $c 'scribed.exe')) -and (Test-Path (Join-Path $c 'scribe.exe'))) { return $c }
    }
    throw 'no scribed.exe found: pass -From <dir> (a release archive), or build with scripts\build\windows.ps1 build -Release'
}

# A build left in target\ by an older checkout installs old code: its version must be this
# checkout's (same rules as scripts/version.sh current). Only for builds found in this repository.
function Assert-Fresh([string]$Bins) {
    if (-not $Root -or -not $Bins.StartsWith((Join-Path $Root 'target'), [StringComparison]::OrdinalIgnoreCase)) { return }
    $have = ((& (Join-Path $Bins 'scribed.exe') --version) -split ' ', 2)[1]
    $describe = & git -C $Root describe --tags --match 'v[0-9]*' --abbrev=7 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $describe) {
        Write-Host "    note: can't tell this checkout's version; installing scribed $have"
        return
    }
    $want = if ($describe -match '^v(.+)-(\d+)-(g[0-9a-f]+)$') { "$($Matches[1])+$($Matches[2]).$($Matches[3])" } else { $describe.TrimStart('v') }
    if ($have -ne $want) {
        throw "$Bins holds scribed $have, but this checkout is ${want}: rebuild (scripts\build\windows.ps1 build -Release) or pass -From $Bins to install it anyway"
    }
}

# A file from the release archive (<bins>\<name>) or this repository (<repo path>).
function Find-File([string]$Bins, [string]$Name, [string]$RepoPath) {
    $a = Join-Path $Bins $Name
    if (Test-Path $a) { return $a }
    if ($Root) {
        $r = Join-Path $Root $RepoPath
        if (Test-Path $r) { return $r }
    }
    throw "$Name not found next to the binaries or in this repository ($RepoPath)"
}

function Get-MachinePath { [Environment]::GetEnvironmentVariable('Path', 'Machine') }
function Set-MachinePath([string]$Value) { [Environment]::SetEnvironmentVariable('Path', $Value, 'Machine') }
function Test-OnPath { (Get-MachinePath) -split ';' | Where-Object { $_.TrimEnd('\') -ieq $Dir.TrimEnd('\') } }

# The MSI puts the same files in place and removes them itself.
function Assert-NoMsi {
    $by = $null
    try { $by = Get-ItemPropertyValue -Path 'HKLM:\Software\scribe' -Name InstalledBy -ErrorAction Stop } catch { }
    if ($by -eq 'msi') { throw 'scribe is installed from its MSI: upgrade it with a newer MSI, or remove it in Settings > Apps (msiexec /x)' }
}

function Install-Scribed {
    Assert-NoMsi
    $bins = Find-Bins
    if (-not $From) { Assert-Fresh $bins }
    $service = Find-File $bins 'install-service.ps1' 'packaging\windows\install-service.ps1'
    $notify = Find-File $bins 'install-notify.ps1' 'packaging\windows\install-notify.ps1'
    $config = Find-File $bins 'scribe.toml' 'config\scribe.toml'
    $version = & (Join-Path $bins 'scribed.exe') --version
    Say "installing $version from $bins to $Dir"

    $installed = Join-Path $Dir 'install-service.ps1'
    if ((Get-Service -Name 'scribed' -ErrorAction SilentlyContinue) -and (Test-Path $installed)) {
        Say 'removing the installed service first (upgrade)'
        & $installed -Remove
    } elseif (Get-Service -Name 'scribed' -ErrorAction SilentlyContinue) {
        throw "a scribed service is installed from elsewhere; remove it first (its install-service.ps1 -Remove)"
    }

    Say 'files'
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    Copy-Item (Join-Path $bins 'scribed.exe'), (Join-Path $bins 'scribe.exe'), $service, $notify $Dir -Force
    $toml = Join-Path $Dir 'scribe.toml'
    if (Test-Path $toml) { Write-Host '    scribe.toml kept (it exists)' } else { Copy-Item $config $toml }

    if (-not (Test-OnPath)) {
        Say "adding $Dir to the system PATH"
        Set-MachinePath (((Get-MachinePath).TrimEnd(';')) + ";$Dir")
    }

    Say 'service'
    if ($LocalSystem) { & $installed -LocalSystem } else { & $installed }

    $pipe = $false
    foreach ($i in 1..30) {
        if (Test-Path '\\.\pipe\scribed') { $pipe = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $pipe) { throw "scribed did not start: see $(Join-Path $Dir 'logs')" }
    Say 'scribed is running'
    Write-Host '    status:        scribe status   (new terminals find scribe on the PATH)'
    Write-Host '    give access:   net localgroup scribe <name> /add   (scribe-admin for control calls)'
    Write-Host "    notifications: $(Join-Path $Dir 'install-notify.ps1')   (as each desktop user)"
}

function Uninstall-Scribed {
    Assert-NoMsi
    $installed = Join-Path $Dir 'install-service.ps1'
    Say 'removing the service'
    if (Test-Path $installed) {
        & $installed -Remove
    } elseif (Get-Service -Name 'scribed' -ErrorAction SilentlyContinue) {
        throw "the scribed service wasn't installed to $Dir; pass -Dir, or remove it with its install-service.ps1 -Remove"
    }
    if (Test-OnPath) {
        Say "removing $Dir from the system PATH"
        Set-MachinePath ((((Get-MachinePath) -split ';') | Where-Object { $_ -and $_.TrimEnd('\') -ine $Dir.TrimEnd('\') }) -join ';')
    }
    if ($Purge) {
        Say 'removing the folder with config, data and logs, and the groups'
        Remove-Item -Recurse -Force $Dir -ErrorAction SilentlyContinue
        foreach ($g in 'scribe-admin', 'scribe') { if (Test-Group $g) { $computer.Delete('Group', $g) } }
    } else {
        foreach ($f in 'scribed.exe', 'scribe.exe', 'install-service.ps1', 'install-notify.ps1') {
            Remove-Item -Force (Join-Path $Dir $f) -ErrorAction SilentlyContinue
        }
        Write-Host "    kept: $Dir (scribe.toml, data, logs) and the groups (-Purge removes them)"
    }
    Say 'scribed removed'
}

if ($Action -eq 'install') { Install-Scribed } else { Uninstall-Scribed }
