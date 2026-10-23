# End-to-end test on Windows. Run as Administrator:
#   .\run.ps1 -Package C:\path\to\scribe.msi
param([Parameter(Mandatory = $true)][string]$Package)
$ErrorActionPreference = "Stop"

Get-Content "$PSScriptRoot\..\traffic.env" | Where-Object { $_ -match '^\w+=' } | ForEach-Object {
    $name, $value = $_ -split '=', 2
    Set-Variable -Name $name -Value $value
}

function Fail($msg) { Write-Error "FAIL: $msg"; exit 1 }
function Step($msg) { Write-Host "== $msg" }
function Expect-Host($h) { if (-not (scribe hosts | Select-String -SimpleMatch $h)) { Fail "host $h not tracked" } }
function Expect-Alert($h) { if (-not (scribe alerts | Select-String -SimpleMatch $h)) { Fail "no alert for $h" } }

Step "install"
Start-Process msiexec.exe -ArgumentList "/i `"$Package`" /qn" -Wait
if ((Get-Service scribed).Status -ne "Running") { Fail "service not running" }
if (-not (scribe status | Select-String "health: ok")) { Fail "daemon not healthy" }

Step "learn"
scribe mode learn
Invoke-WebRequest "https://$TLS_HOST/" -UseBasicParsing | Out-Null
Invoke-WebRequest "http://$PLAIN_HOST/" -UseBasicParsing | Out-Null
Start-Sleep 2
Expect-Host $TLS_HOST
Expect-Host $PLAIN_HOST
if (scribe alerts | Select-String .) { Fail "learn mode raised alerts" }

Step "caution"
scribe mode caution
Invoke-WebRequest "http://$PLAIN_HOST/" -UseBasicParsing | Out-Null
Test-NetConnection $RAW_IP -Port $RAW_PORT -WarningAction SilentlyContinue | Out-Null
Start-Sleep 2
Expect-Alert $PLAIN_HOST
Expect-Alert $RAW_IP

Step "alert"
scribe mode alert
Invoke-WebRequest "https://$TLS_HOST_NEW/" -UseBasicParsing | Out-Null
Start-Sleep 2
Expect-Alert $TLS_HOST_NEW

Step "upgrade (reinstall)"
Start-Process msiexec.exe -ArgumentList "/i `"$Package`" /qn REINSTALL=ALL REINSTALLMODE=vomus" -Wait
Expect-Host $TLS_HOST

Step "uninstall"
Start-Process msiexec.exe -ArgumentList "/x `"$Package`" /qn" -Wait
if (Get-Service scribed -ErrorAction SilentlyContinue) { Fail "service left behind" }
if (Get-Command scribe -ErrorAction SilentlyContinue) { Fail "cli left behind" }

Write-Host "PASS"
