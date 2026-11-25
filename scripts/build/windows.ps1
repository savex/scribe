<#
.SYNOPSIS
  Build, test and package scribe on Windows x64.

.DESCRIPTION
  scripts\build\windows.ps1 doctor           check the toolchain and say what's missing
  scripts\build\windows.ps1 build [-Release]
  scripts\build\windows.ps1 test
  scripts\build\windows.ps1 check            fmt, clippy, tests, doc examples, fixtures, MSRV
                                             (+ test tags and the version script when Git Bash is installed)
  scripts\build\windows.ps1 release          dist\ zip for x86_64-pc-windows-msvc, smoke-tested
  scripts\build\windows.ps1 service-test     install, start, stop and remove the service (Administrator)
  scripts\build\windows.ps1 clean

  Works in PowerShell 7 and Windows PowerShell 5.1. If scripts are blocked:
    pwsh -ExecutionPolicy Bypass -File scripts\build\windows.ps1 doctor
  Settings come from scripts\build\config (shared with the macOS and Linux scripts).
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('doctor', 'build', 'test', 'check', 'release', 'service-test', 'clean', 'help')]
    [string]$Command = 'help',
    [switch]$Release
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Target = 'x86_64-pc-windows-msvc'

# Settings from scripts\build\config, unless set in the environment.
$Config = @{}
foreach ($line in Get-Content (Join-Path $PSScriptRoot 'config')) {
    if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
    $key, $value = $line -split '=', 2
    $fromEnv = [Environment]::GetEnvironmentVariable($key)
    if ($fromEnv) { $Config[$key] = $fromEnv } else { $Config[$key] = $value }
}

# rustup installs into the user profile; a fresh shell may not have it on PATH yet.
$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
if ((Test-Path $cargoBin) -and ($env:PATH -notlike "*$cargoBin*")) { $env:PATH = "$cargoBin;$env:PATH" }

function Say([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }

# Run a program; stop when it fails.
function Invoke-Tool([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE" }
}

function Get-Msrv {
    $line = Select-String -Path (Join-Path $Root 'Cargo.toml') -Pattern '^rust-version\s*=\s*"([^"]+)"' | Select-Object -First 1
    return $line.Matches[0].Groups[1].Value
}

# Same rules as scripts/version.sh current and crates/core/build.rs (no dirty marker).
function Get-BuildVersion {
    $describe = & git -C $Root describe --tags --match 'v[0-9]*' --abbrev=7 2>$null
    if ($LASTEXITCODE -eq 0 -and $describe) {
        if ($describe -match '^v(.+)-(\d+)-(g[0-9a-f]+)$') { return "$($Matches[1])+$($Matches[2]).$($Matches[3])" }
        return $describe.TrimStart('v')
    }
    $cargo = Select-String -Path (Join-Path $Root 'Cargo.toml') -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    return $cargo.Matches[0].Groups[1].Value
}

function Test-X64 {
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
    return $arch -eq 'AMD64'
}

function Find-VsTools {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { return $null }
    $path = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -eq 0 -and $path) { return $path }
    return $null
}

function Find-Bash {
    $gitBash = Join-Path $env:ProgramFiles 'Git\bin\bash.exe'
    if (Test-Path $gitBash) { return $gitBash }
    return $null
}

function Invoke-Doctor {
    $msrv = Get-Msrv
    function Check([string]$Name, [scriptblock]$Test, [string]$Fix) {
        $ok = $false
        try { $ok = [bool](& $Test) } catch { $ok = $false }
        if ($ok) { Write-Host "  ok       $Name" } else { Write-Host "  MISSING  $Name - $Fix" -ForegroundColor Yellow; $script:missing++ }
    }
    $script:missing = 0
    Say 'Windows toolchain'
    Check 'Windows x64' { Test-X64 } 'this script builds x86_64-pc-windows-msvc on an x64 machine'
    Check 'Visual Studio C++ build tools' { Find-VsTools } 'install "Desktop development with C++" or the Build Tools for Visual Studio'
    Check 'Windows SDK' { Test-Path (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Include') } 'install a Windows 10/11 SDK with the Visual Studio installer'
    Check 'git' { Get-Command git -ErrorAction SilentlyContinue } 'https://git-scm.com (Git Bash also runs the tag and version checks)'
    Check 'rustup' { Get-Command rustup -ErrorAction SilentlyContinue } 'https://rustup.rs'
    # Programs' own output is discarded so only the exit code decides.
    Check 'Rust stable (MSVC)' { & rustup run stable-x86_64-pc-windows-msvc rustc --version *> $null; $LASTEXITCODE -eq 0 } 'rustup toolchain install stable-x86_64-pc-windows-msvc'
    Check "Rust $msrv (MSRV)" { & rustup run $msrv rustc --version *> $null; $LASTEXITCODE -eq 0 } "rustup toolchain install $msrv"
    Check 'cargo-nextest' { & cargo nextest --version *> $null; $LASTEXITCODE -eq 0 } "cargo install --locked cargo-nextest@$($Config.NEXTEST_VERSION)"
    Check 'Git Bash (optional: tag and version checks)' { Find-Bash } 'comes with Git for Windows'
    Check 'Npcap SDK (phase 6: pcap sensor)' { $env:NPCAP_SDK -and (Test-Path $env:NPCAP_SDK) } 'optional now: download the Npcap SDK and set NPCAP_SDK to its folder'
    # Npcap SDK and Git Bash are optional today; the rest is required.
    $required = $script:missing
    if (-not (Find-Bash)) { $required-- }
    if (-not ($env:NPCAP_SDK -and (Test-Path $env:NPCAP_SDK))) { $required-- }
    if ($required -gt 0) { throw 'install what is missing, then run doctor again' }
    Say 'all set'
}

function Invoke-CargoBuild([bool]$IsRelease) {
    $arguments = @('build', '--locked', '--target', $Target)
    if ($IsRelease) { $arguments += '--release' }
    foreach ($p in ($Config.RELEASE_PACKAGES -split ' ')) { if ($p) { $arguments += @('-p', $p) } }
    Say "build $Target ($(if ($IsRelease) { 'release' } else { 'debug' }))"
    Invoke-Tool cargo $arguments
}

function Confirm-Nextest {
    & cargo nextest --version *> $null
    if ($LASTEXITCODE -ne 0) {
        Say "installing cargo-nextest $($Config.NEXTEST_VERSION)"
        Invoke-Tool cargo @('install', '--locked', "cargo-nextest@$($Config.NEXTEST_VERSION)")
    }
}

function Invoke-Checks {
    Confirm-Nextest
    $msrv = Get-Msrv
    Say 'fmt';          Invoke-Tool cargo @('fmt', '--all', '--check')
    Say 'clippy';       Invoke-Tool cargo @('clippy', '--workspace', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings')
    Say 'tests';        Invoke-Tool cargo @('nextest', 'run', '--workspace', '--all-features', '--locked')
    Say 'doc examples'; Invoke-Tool cargo @('test', '--workspace', '--all-features', '--locked', '--doc', '-q')
    $bash = Find-Bash
    if ($bash) {
        Say 'test tags';      Invoke-Tool $bash @('scripts/check-test-tags.sh')
        Say 'version script'; Invoke-Tool $bash @('scripts/test-version.sh')
    } else {
        Write-Warning 'Git Bash not found: test tags and the version script are checked on macOS, Linux and CI'
    }
    Say 'fixtures';     Invoke-Tool cargo @('run', '-q', '--locked', '-p', 'scribe-test-support', '--bin', 'gen-fixtures', '--', '--check')
    Say "msrv $msrv";   Invoke-Tool cargo @("+$msrv", 'check', '--workspace', '--all-targets', '--all-features', '--locked', '-q')
    Say 'all checks passed'
}

# Same checks as .github/workflows/release.yml.
function Invoke-Smoke([string]$Dir, [string]$Version) {
    $got = & (Join-Path $Dir 'scribe.exe') --version
    if ($got -ne "scribe $Version") { throw "scribe reports '$got', expected 'scribe $Version'" }
    $got = & (Join-Path $Dir 'scribed.exe') --version
    if ($got -ne "scribed $Version") { throw "scribed reports '$got', expected 'scribed $Version'" }
    $effective = & (Join-Path $Dir 'scribed.exe') --check-config --config (Join-Path $Dir 'scribe.toml')
    if ($LASTEXITCODE -ne 0) { throw 'scribed rejects the shipped config' }
    if (-not ($effective -match '^\[modules\.url\]')) { throw 'the URL module is missing from the effective config' }
    Say "smoke test passed: $Version"
}

# dist\scribe-<version>-x86_64-pc-windows-msvc.zip, laid out as release.yml lays it out, added to dist\SHA256SUMS.
function Invoke-Release {
    $version = Get-BuildVersion
    $env:SCRIBE_VERSION = $version
    Invoke-CargoBuild $true
    $name = "scribe-$version-$Target"
    $dist = Join-Path $Root 'dist'
    $out = Join-Path $dist $name
    if (Test-Path $out) { Remove-Item -Recurse -Force $out }
    New-Item -ItemType Directory -Force -Path (Join-Path $out 'service') | Out-Null
    $bins = Join-Path $Root "target\$Target\release"
    Copy-Item (Join-Path $bins 'scribed.exe'), (Join-Path $bins 'scribe.exe') $out
    Copy-Item (Join-Path $Root 'readme.md'), (Join-Path $Root 'config\scribe.toml') $out
    Copy-Item (Join-Path $Root 'packaging\README.md') (Join-Path $out 'service')
    Copy-Item (Join-Path $Root 'packaging\windows\install-service.ps1') $out
    Invoke-Smoke $out $version
    $zip = Join-Path $dist "$name.zip"
    if (Test-Path $zip) { Remove-Item -Force $zip }
    Compress-Archive -Path $out -DestinationPath $zip
    Remove-Item -Recurse -Force $out

    # SHA256SUMS: "<hash>  <file>" lines with LF endings, sorted by file name, as sha256sum writes them.
    $sums = Join-Path $dist 'SHA256SUMS'
    $lines = @()
    if (Test-Path $sums) { $lines = @(Get-Content $sums | Where-Object { $_ -and $_ -notmatch "  $([regex]::Escape("$name.zip"))$" }) }
    $hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
    $lines += "$hash  $name.zip"
    $sorted = $lines | Sort-Object { ($_ -split '  ', 2)[1] }
    [IO.File]::WriteAllText($sums, (($sorted -join "`n") + "`n"))
    Say "packaged dist\$name.zip"
}

# Install the release build as a service from a throwaway folder, start it, stop it, remove it.
function Invoke-ServiceTest {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'service-test needs an Administrator shell'
    }
    if (Get-Service -Name 'scribed' -ErrorAction SilentlyContinue) { throw 'a scribed service is already installed; remove it first' }
    Invoke-CargoBuild $true
    $dir = Join-Path ([IO.Path]::GetTempPath()) ("scribe-service-test-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    try {
        $bins = Join-Path $Root "target\$Target\release"
        Copy-Item (Join-Path $bins 'scribed.exe') $dir
        Copy-Item (Join-Path $Root 'packaging\windows\install-service.ps1') $dir
        $data = (Join-Path $dir 'data') -replace '\\', '/'
        Set-Content -Path (Join-Path $dir 'scribe.toml') -Value "data_dir = '$data'`n[log]`nfile = 'logs/scribed.log'`n"
        Say 'install and start'
        & (Join-Path $dir 'install-service.ps1')
        $service = Get-Service -Name 'scribed'
        $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        $as = (Get-CimInstance Win32_Service -Filter "Name='scribed'").StartName
        if ($as -ne 'NT SERVICE\scribed') { throw "the service runs as '$as', not NT SERVICE\scribed" }
        Start-Sleep -Seconds 2
        Say 'stop'
        Stop-Service -Name 'scribed'
        (Get-Service -Name 'scribed').WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        if (Test-Path (Join-Path $dir 'data\scribed.running')) { throw 'scribed did not stop cleanly (its running marker is still there)' }
        Say 'service test passed'
    } finally {
        & (Join-Path $dir 'install-service.ps1') -Remove
        Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
    }
}

Set-Location $Root
switch ($Command) {
    'doctor'       { Invoke-Doctor }
    'build'        { Invoke-CargoBuild $Release.IsPresent }
    'test'         { Confirm-Nextest; Say 'tests'; Invoke-Tool cargo @('nextest', 'run', '--workspace', '--all-features', '--locked') }
    'check'        { Invoke-Checks }
    'release'      { Invoke-Release }
    'service-test' { Invoke-ServiceTest }
    'clean'        { Invoke-Tool cargo @('clean'); if (Test-Path (Join-Path $Root 'dist')) { Remove-Item -Recurse -Force (Join-Path $Root 'dist') } }
    default        { Get-Help $PSCommandPath -Detailed }
}
