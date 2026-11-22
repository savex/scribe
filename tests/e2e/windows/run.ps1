# End-to-end test on Windows, as Administrator, on a clean lab VM:
#   .\run.ps1 -Previous C:\path\to\previous.msi -Package C:\path\to\scribe.msi [-Purge]
# Targets come from ..\traffic.env (lab servers only). Config, data and logs live next to scribed.exe
# and must survive an uninstall unless -Purge is given (specs 9.1).
param(
    [Parameter(Mandatory = $true)][string]$Previous,
    [Parameter(Mandatory = $true)][string]$Package,
    [switch]$Purge
)
$ErrorActionPreference = "Stop"

Get-Content "$PSScriptRoot\..\traffic.env" | Where-Object { $_ -match '^\w+=' } | ForEach-Object {
    $name, $value = $_ -split '=', 2
    Set-Variable -Name $name -Value $value
}

function Fail($msg) { Write-Error "FAIL: $msg"; exit 1 }
function Step($msg) { Write-Host "== $msg" }
foreach ($v in "TLS_HOST", "TLS_HOST_NEW", "PLAIN_HOST", "RAW_IP") {
    if (-not (Get-Variable $v -ValueOnly)) { Fail "$v is empty in traffic.env (point it at a lab server)" }
}
$InstallDir = "$env:ProgramFiles\scribe"

function Wait-For($what, [scriptblock]$check) {
    for ($i = 0; $i -lt 30; $i++) {
        try { if (& $check) { return } } catch {}
        Start-Sleep -Milliseconds 500
    }
    Fail "timed out: $what"
}
function Hosts { scribe hosts --json | ConvertFrom-Json }
function Alerts { scribe alerts --json | ConvertFrom-Json }
function Status { scribe daemon status --json | ConvertFrom-Json }
function Has-Host($h) { [bool]((Hosts).items | Where-Object { $_.name -eq $h }) }
function Has-Alert($h) { [bool]((Alerts).items | Where-Object { $_.host -eq $h -or $_.dst -like "${h}:*" }) }
function Healthy { scribe daemon health | Out-Null; $LASTEXITCODE -eq 0 }
function Tls($h) { try { Invoke-WebRequest "https://$h/" -UseBasicParsing | Out-Null } catch {} }
function Plain { try { Invoke-WebRequest "http://$PLAIN_HOST$PLAIN_PATH" -UseBasicParsing | Out-Null } catch {} }
function Raw { Test-NetConnection $RAW_IP -Port $RAW_PORT -WarningAction SilentlyContinue | Out-Null }
function Msi($ArgList) { $p = Start-Process msiexec.exe -ArgumentList $ArgList -Wait -PassThru; if ($p.ExitCode -ne 0) { Fail "msiexec $ArgList exited $($p.ExitCode)" } }

Step "install previous release"
Msi "/i `"$Previous`" /qn"
Wait-For "service running" { (Get-Service scribed).Status -eq "Running" }
Wait-For "daemon healthy" { Healthy }

Step "learn (previous release)"
scribe mode learn
Tls $TLS_HOST; Plain
Wait-For "host $TLS_HOST tracked" { Has-Host $TLS_HOST }
Wait-For "host $PLAIN_HOST tracked" { Has-Host $PLAIN_HOST }
if ((Alerts).items.Count -ne 0) { Fail "learn mode raised alerts" }
scribe mode caution

Step "upgrade to the new package"
Msi "/i `"$Package`" /qn"
Wait-For "daemon healthy after upgrade" { Healthy }
if (-not (Has-Host $TLS_HOST)) { Fail "hosts lost in the upgrade" }
if ((Status).mode -ne "caution") { Fail "mode lost in the upgrade" }
if (-not ((scribe baseline --json | ConvertFrom-Json).entries | Where-Object { $_.host -eq $TLS_HOST })) { Fail "baseline lost in the upgrade" }
if (-not (scribed --check-config --config "$InstallDir\scribe.toml" | Select-String '^\[modules.url\]')) { Fail "installed config not valid" }
if (-not ((scribe modules --json | ConvertFrom-Json) | Where-Object { $_.id -eq "url" -and $_.state -eq "running" })) { Fail "URL module not running" }

Step "security"
$acl = (Get-Acl "$InstallDir\scribe.toml").Access | Where-Object { $_.IdentityReference -match "Users|Everyone" -and $_.FileSystemRights -match "Write|Modify|FullControl" }
if ($acl) { Fail "scribe.toml is writable by ordinary users" }

Step "caution"
Tls $TLS_HOST; Plain; Raw
Wait-For "plaintext alert for $PLAIN_HOST" { Has-Alert $PLAIN_HOST }
Wait-For "alert for raw IP $RAW_IP" { Has-Alert $RAW_IP }
if (-not ((Alerts).items | Where-Object { $_.host -eq $PLAIN_HOST -and $_.reason -eq "plaintext" -and $_.notes.url -like "http://*" })) { Fail "plaintext alert without its URL note" }
if (Has-Alert $TLS_HOST) { Fail "known TLS host raised an alert" }

Step "alert"
scribe mode alert
Tls $TLS_HOST_NEW
Wait-For "alert for new host $TLS_HOST_NEW" { Has-Alert $TLS_HOST_NEW }

Step "daemon commands"
scribe daemon hibernate --for 1m
Wait-For "hibernating" { (Status).run_state -eq "hibernating" }
if (-not ((Alerts).items | Where-Object { $_.reason -eq "hibernated" })) { Fail "no hibernated alert" }
scribe daemon wakeup
Wait-For "running again" { (Status).run_state -eq "running" }

Step "uninstall"
Msi "/x `"$Package`" /qn"
if (Get-Service scribed -ErrorAction SilentlyContinue) { Fail "service left behind" }
if (Test-Path "$InstallDir\scribed.exe") { Fail "binaries left behind" }
if ($Purge) {
    Remove-Item -Recurse -Force "$InstallDir" -ErrorAction SilentlyContinue
    if (Test-Path "$InstallDir\data") { Fail "data left behind after -Purge" }
} else {
    foreach ($p in "scribe.toml", "data\state.db", "logs") {
        if (-not (Test-Path "$InstallDir\$p")) { Fail "$p removed by uninstall" }
    }
}

Write-Host "PASS"
