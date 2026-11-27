<#
.SYNOPSIS
  Builds the scribe MSI (plan phase 13) with WiX from packaging\windows\scribe.wxs.

.DESCRIPTION
  scripts\build\windows-msi.ps1 -Bins <folder with scribed.exe and scribe.exe> [-Version <version>] [-Out <file>]

  Writes dist\scribe-<version>-x86_64-pc-windows-msvc.msi (or -Out) and prints its path; the caller
  adds checksums (scripts\build\windows.ps1 release, .github\workflows\release.yml). -Version
  defaults to SCRIBE_VERSION, else the version scribed.exe reports; the MSI's own version is its x.y.z (MSI versions are numbers only),
  and every build gets a new ProductCode, so any build upgrades any other of the same version.
  WiX WIX_VERSION (scripts\build\config) is installed as a .NET tool into target\tools\ when
  missing, with the Util extension of the same version. Needs the .NET SDK (8 or newer).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Bins,
    [string]$Version = $env:SCRIBE_VERSION,
    [string]$Out
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Config = @{}
foreach ($line in Get-Content (Join-Path $PSScriptRoot 'config')) {
    if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
    $key, $value = $line -split '=', 2
    $fromEnv = [Environment]::GetEnvironmentVariable($key)
    if ($fromEnv) { $Config[$key] = $fromEnv } else { $Config[$key] = $value }
}
$wixVersion = $Config['WIX_VERSION']

$Bins = (Resolve-Path $Bins).Path
foreach ($exe in 'scribed.exe', 'scribe.exe') {
    if (-not (Test-Path (Join-Path $Bins $exe))) { throw "no $exe in $Bins" }
}
if (-not $Version) {
    # The version the binary reports: `scribed <version>`.
    $Version = ((& (Join-Path $Bins 'scribed.exe') --version) -split ' ', 2)[1]
    if (-not $Version) { throw 'pass -Version: scribed.exe --version printed nothing' }
}
if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)') { throw "version $Version does not start with x.y.z" }
$msiVersion = $Matches[0]
if (-not $Out) { $Out = Join-Path $Root "dist\scribe-$Version-x86_64-pc-windows-msvc.msi" }
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null

# WiX as a .NET tool in target\tools\wix-<version>, its extensions in the same folder (WIX_EXTENSIONS).
$tools = Join-Path $Root "target\tools\wix-$wixVersion"
$wix = Join-Path $tools 'wix.exe'
if (-not (Test-Path $wix)) {
    Write-Host "==> installing WiX $wixVersion" -ForegroundColor Cyan
    & dotnet tool install wix --version $wixVersion --tool-path $tools | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "dotnet tool install wix $wixVersion failed ($LASTEXITCODE)" }
}
$env:WIX_EXTENSIONS = $tools
$ext = "WixToolset.Util.wixext/$wixVersion"
& $wix extension add -g $ext | Out-Host
if ($LASTEXITCODE -ne 0 -and -not (& $wix extension list -g | Select-String -SimpleMatch 'WixToolset.Util.wixext')) {
    throw "wix extension add $ext failed ($LASTEXITCODE)"
}

Write-Host "==> building $(Split-Path -Leaf $Out) (MSI version $msiVersion)" -ForegroundColor Cyan
& $wix build (Join-Path $Root 'packaging\windows\scribe.wxs') -arch x64 -ext $ext `
    -d "Version=$msiVersion" -d "Bins=$Bins" -d "Root=$Root" -o $Out | Out-Host
if ($LASTEXITCODE -ne 0) { throw "wix build failed ($LASTEXITCODE)" }
Remove-Item -Force -ErrorAction SilentlyContinue ([IO.Path]::ChangeExtension($Out, '.wixpdb'))
Write-Output $Out
