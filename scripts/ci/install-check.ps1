# Sensors workflow, Windows (Administrator): scripts\install\windows.ps1 installs scribed to
# Program Files from a build, scribe on the PATH reads its status, a second install upgrades in
# place and `uninstall -Purge` leaves nothing behind.
#
#   install-check.ps1 <folder with scribed.exe and scribe.exe>
param([Parameter(Mandatory)] [string]$Bin)
$ErrorActionPreference = 'Stop'

$install = Join-Path $PSScriptRoot '..\install\windows.ps1'
$dir = Join-Path $env:ProgramFiles 'scribe'
function Fail([string]$Text) {
    Write-Host "::error::$Text"
    throw $Text
}
function Test-Group([string]$Name) { [ADSI]::Exists("WinNT://$env:COMPUTERNAME/$Name,group") }

if (Get-Service -Name 'scribed' -ErrorAction SilentlyContinue) { Fail 'a scribed service is already installed' }
$ok = $false
try {
    & $install install -From $Bin
    $start = (Get-CimInstance Win32_Service -Filter "Name='scribed'").StartName
    if ($start -ne 'NT SERVICE\scribed') { Fail "the service runs as '$start'" }
    if (-not ((Test-Group 'scribe') -and (Test-Group 'scribe-admin'))) { Fail 'the groups were not created' }
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';'
    if ($path -notcontains $dir) { Fail "$dir is not on the system PATH" }
    $status = & (Join-Path $dir 'scribe.exe') status | Out-String
    Write-Host $status
    if ($status -notmatch 'windows-etw') { Fail 'scribed does not capture with the ETW sensor' }

    # Upgrade in place: the config stays.
    Add-Content -Path (Join-Path $dir 'scribe.toml') -Value '# kept across upgrades'
    & $install install -From $Bin
    if (-not (Select-String -Path (Join-Path $dir 'scribe.toml') -Pattern 'kept across upgrades' -Quiet)) { Fail 'the upgrade replaced scribe.toml' }
    & (Join-Path $dir 'scribe.exe') status | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 'scribed did not come back after the upgrade' }

    & $install uninstall -Purge
    if (Get-Service -Name 'scribed' -ErrorAction SilentlyContinue) { Fail 'the service is still installed' }
    if (Test-Path $dir) { Fail "$dir left after -Purge" }
    if ((Test-Group 'scribe') -or (Test-Group 'scribe-admin')) { Fail 'groups left after -Purge' }
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';'
    if ($path -contains $dir) { Fail "$dir still on the system PATH" }
    Write-Host 'install check passed'
    $ok = $true
} finally {
    if (-not $ok) {
        foreach ($f in Get-ChildItem (Join-Path $dir 'logs') -File -ErrorAction SilentlyContinue) {
            Write-Host "--- $($f.Name)"
            Get-Content $f.FullName -Tail 60
        }
        if (Test-Path $dir) { & $install uninstall -Purge }
    }
}
