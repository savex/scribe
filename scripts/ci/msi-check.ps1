# Sensors workflow, Windows (Administrator, .NET SDK): the MSI from scripts\build\windows-msi.ps1.
# Two builds of the same binaries (each has its own ProductCode): the first installs scribed as
# NT SERVICE\scribed with ETW, on the PATH, with the groups; the second upgrades it in place and
# keeps the changed scribe.toml; uninstalling removes the service, the programs and the PATH entry
# and keeps scribe.toml, data and logs.
#
#   msi-check.ps1 <folder with scribed.exe and scribe.exe>
param([Parameter(Mandatory)] [string]$Bin)
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dir = Join-Path $env:ProgramFiles 'scribe'
$work = Join-Path $root 'target\msi-check'
function Fail([string]$Text) {
    Write-Host "::error::$Text"
    throw $Text
}
function Test-Group([string]$Name) { [ADSI]::Exists("WinNT://$env:COMPUTERNAME/$Name,group") }
function Install-Msi([string]$Msi, [string]$Log) {
    $p = Start-Process msiexec.exe -ArgumentList '/i', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$Log`"" -Wait -PassThru
    if ($p.ExitCode -ne 0) { Fail "msiexec /i $(Split-Path -Leaf $Msi) exited with $($p.ExitCode)" }
}
function Get-Products {
    @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' |
        Get-ItemProperty | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -eq 'scribe' })
}
function Wait-Status {
    foreach ($i in 1..30) {
        $out = & (Join-Path $dir 'scribe.exe') status 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) { return $out }
        Start-Sleep -Seconds 1
    }
    Fail "scribe status fails: $out"
}

if (Get-Service -Name 'scribed' -ErrorAction SilentlyContinue) { Fail 'a scribed service is already installed' }
if (Test-Path $dir) { Fail "$dir exists" }
New-Item -ItemType Directory -Force -Path $work | Out-Null
$first = Join-Path $work 'first.msi'
$second = Join-Path $work 'second.msi'
& (Join-Path $root 'scripts\build\windows-msi.ps1') -Bins $Bin -Out $first | Out-Null
& (Join-Path $root 'scripts\build\windows-msi.ps1') -Bins $Bin -Out $second | Out-Null

$ok = $false
try {
    Install-Msi $first (Join-Path $work 'install.log')
    $start = (Get-CimInstance Win32_Service -Filter "Name='scribed'").StartName
    if ($start -ne 'NT SERVICE\scribed') { Fail "the service runs as '$start'" }
    if (-not ((Test-Group 'scribe') -and (Test-Group 'scribe-admin'))) { Fail 'the groups were not created' }
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' | ForEach-Object { $_.TrimEnd('\') }
    if ($path -notcontains $dir) { Fail "$dir is not on the system PATH" }
    $status = Wait-Status
    Write-Host $status
    if ($status -notmatch 'windows-etw') { Fail 'scribed does not capture with the ETW sensor' }
    if ((Get-Products).Count -ne 1) { Fail "$((Get-Products).Count) scribe entries in Apps after the install" }

    # Upgrade: a second build replaces the first, the edited config stays.
    Add-Content -Path (Join-Path $dir 'scribe.toml') -Value '# kept across upgrades'
    Install-Msi $second (Join-Path $work 'upgrade.log')
    if (-not (Select-String -Path (Join-Path $dir 'scribe.toml') -Pattern 'kept across upgrades' -Quiet)) { Fail 'the upgrade replaced scribe.toml' }
    if ((Get-Products).Count -ne 1) { Fail "$((Get-Products).Count) scribe entries in Apps after the upgrade" }
    if ((Get-Service -Name 'scribed').Status -ne 'Running') { Fail 'scribed is not running after the upgrade' }
    Wait-Status | Out-Null

    $p = Start-Process msiexec.exe -ArgumentList '/x', "`"$second`"", '/qn', '/norestart', '/l*v', "`"$(Join-Path $work 'uninstall.log')`"" -Wait -PassThru
    if ($p.ExitCode -ne 0) { Fail "msiexec /x exited with $($p.ExitCode)" }
    if (Get-Service -Name 'scribed' -ErrorAction SilentlyContinue) { Fail 'the service is still installed' }
    foreach ($f in 'scribed.exe', 'scribe.exe', 'install-service.ps1') {
        if (Test-Path (Join-Path $dir $f)) { Fail "$f left after the uninstall" }
    }
    if (-not (Test-Path (Join-Path $dir 'scribe.toml'))) { Fail 'the uninstall removed scribe.toml' }
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' | ForEach-Object { $_.TrimEnd('\') }
    if ($path -contains $dir) { Fail "$dir still on the system PATH" }
    if ((Get-Products).Count -ne 0) { Fail 'scribe still listed in Apps' }
    Write-Host 'MSI check passed'
    $ok = $true
} finally {
    if (-not $ok) {
        foreach ($f in Get-ChildItem (Join-Path $dir 'logs') -File -ErrorAction SilentlyContinue) {
            Write-Host "--- $($f.Name)"
            Get-Content $f.FullName -Tail 60
        }
        foreach ($log in Get-ChildItem $work -Filter '*.log' -ErrorAction SilentlyContinue) {
            Write-Host "--- $($log.Name) (errors and custom actions)"
            Select-String -Path $log.FullName -Pattern 'Return value 3|error|WixQuietExec|CustomAction' -SimpleMatch:$false |
                Select-Object -Last 60 | ForEach-Object { $_.Line }
        }
        foreach ($code in (Get-Products).PSChildName) {
            Start-Process msiexec.exe -ArgumentList '/x', $code, '/qn', '/norestart' -Wait | Out-Null
        }
    }
    Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
    $computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
    foreach ($g in 'scribe-admin', 'scribe') { if (Test-Group $g) { $computer.Delete('Group', $g) } }
    Remove-Item -Path 'HKLM:\Software\scribe' -Recurse -Force -ErrorAction SilentlyContinue
}
