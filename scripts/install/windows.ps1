<#
.SYNOPSIS
  Installs or removes scribed as a Windows service by hand, until the MSI of plan phase 13 does it.
  Run from an Administrator PowerShell.

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
             (target\x86_64-pc-windows-msvc\release, target\release).

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
function New-Group([string]$Name, [string]$What) {
    if (Test-Group $Name) { return }
    $g = $computer.Create('Group', $Name)
    $g.Put('Description', $What)
    $g.SetInfo()
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

function Install-Scribed {
    $bins = Find-Bins
    $service = Find-File $bins 'install-service.ps1' 'packaging\windows\install-service.ps1'
    $notify = Find-File $bins 'install-notify.ps1' 'packaging\windows\install-notify.ps1'
    $config = Find-File $bins 'scribe.toml' 'config\scribe.toml'
    $version = & (Join-Path $bins 'scribed.exe') --version
    Say "installing $version from $bins to $Dir"

    # The groups must exist before scribed creates its pipe (they are read into its access list).
    Say 'groups'
    New-Group 'scribe' 'scribe API (read)'
    New-Group 'scribe-admin' 'scribe API (control)'

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
