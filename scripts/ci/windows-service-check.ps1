# Sensors workflow, Windows (Administrator): scribed installed as a service running as
# NT SERVICE\scribed (packaging/windows/install-service.ps1) captures with the ETW session and
# names the process of a connection made by another account, with no rights over that process.
#
#   windows-service-check.ps1 <folder with scribed.exe and scribe.exe>
param([Parameter(Mandatory)] [string]$Bin)
$ErrorActionPreference = 'Stop'

function Fail([string]$Text) {
    Write-Host "::error::$Text"
    throw $Text
}

if (Get-Service -Name 'scribed' -ErrorAction SilentlyContinue) { Fail 'a scribed service is already installed' }
$dir = Join-Path $env:RUNNER_TEMP 'scribe-service'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Copy-Item (Join-Path $Bin 'scribed.exe'), (Join-Path $Bin 'scribe.exe') $dir
Copy-Item (Join-Path $PSScriptRoot '..\..\packaging\windows\install-service.ps1') $dir
$slash = $dir -replace '\\', '/'
Set-Content -Path (Join-Path $dir 'scribe.toml') -Value @"
mode = 'learn'
data_dir = '$slash/data'
[log]
file = '$slash/logs/scribed.log'
"@
$scribe = Join-Path $dir 'scribe.exe'
$env:SCRIBE_CONFIG = $null

try {
    & (Join-Path $dir 'install-service.ps1')
    (Get-Service -Name 'scribed').WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

    $start = (Get-CimInstance Win32_Service -Filter "Name='scribed'").StartName
    if ($start -ne 'NT SERVICE\scribed') { Fail "the service runs as '$start', not NT SERVICE\scribed" }
    $svcPid = (Get-CimInstance Win32_Service -Filter "Name='scribed'").ProcessId
    $user = (Get-Process -Id $svcPid -IncludeUserName).UserName
    Write-Host "scribed (pid $svcPid) runs as $user"
    if ($user -ne 'NT SERVICE\scribed') { Fail "scribed's process runs as '$user'" }

    # The API: the client accepts a pipe server running as the service account.
    $status = ''
    foreach ($i in 1..30) {
        $status = & $scribe status 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and $status -match 'windows-etw') { break }
        Start-Sleep -Seconds 1
    }
    Write-Host $status
    if ($status -notmatch 'windows-etw') { Fail 'scribed does not capture with the ETW sensor as NT SERVICE\scribed' }

    # A connection by this (another) account to example.com (Kernel-Network reports connections that
    # are made, not attempts that fail). Its path must come from Kernel-Process: scribed can't open
    # this process.
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    & $curl --silent --max-time 10 --output NUL http://example.com/
    if ($LASTEXITCODE -ne 0) { Fail "curl could not reach example.com ($LASTEXITCODE)" }
    $hosts = ''
    foreach ($i in 1..20) {
        Start-Sleep -Seconds 1
        $hosts = & $scribe hosts 2>&1 | Out-String
        if ($hosts -match 'example\.com' -and $hosts -match 'curl\.exe') { break }
    }
    Write-Host $hosts
    if ($hosts -notmatch 'example\.com') { Fail 'the connection to example.com was not recorded' }
    if ($hosts -notmatch 'curl\.exe') { Fail 'the connection to example.com has no process path' }

    Stop-Service -Name 'scribed'
    (Get-Service -Name 'scribed').WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    if (Test-Path (Join-Path $dir 'data\scribed.running')) { Fail 'scribed did not stop cleanly (its running marker is still there)' }
    Write-Host 'service check passed'
} catch {
    Write-Host '--- service'
    Get-CimInstance Win32_Service -Filter "Name='scribed'" | Format-List State, Status, ExitCode, ServiceSpecificExitCode, ProcessId, StartName
    Write-Host '--- Service Control Manager events'
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddMinutes(-10) } -ErrorAction SilentlyContinue |
        Select-Object -First 10 | Format-List TimeCreated, Id, Message
    Write-Host '--- files and access'
    Get-ChildItem -Recurse $dir | Format-Table FullName, Length -AutoSize
    foreach ($p in $dir, (Join-Path $dir 'data'), (Join-Path $dir 'logs'), (Join-Path $dir 'scribe.toml')) { & icacls.exe $p }
    throw
} finally {
    # Rotated logs carry a date suffix (scribed.log.2026-11-25).
    foreach ($f in Get-ChildItem (Join-Path $dir 'logs') -File -ErrorAction SilentlyContinue) {
        Write-Host "--- $($f.Name)"
        Get-Content $f.FullName -Tail 60
    }
    & (Join-Path $dir 'install-service.ps1') -Remove
}
