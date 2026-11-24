# Desktop notifications for scribe alerts (plan phase 11): starts `scribe notify` at logon for the
# current user. The scribed service runs in session 0 and can't show toasts, so the agent runs in
# the user's session and follows scribed's alert stream. Run as that user (no Administrator needed)
# from the folder that holds scribe.exe. The MSI does this for every user from phase 13.
#   .\install-notify.ps1            start at logon, and now
#   .\install-notify.ps1 -Remove    stop starting at logon
param([switch]$Remove)
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$name = 'scribe-notify'
if ($Remove) {
    Remove-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
    Write-Host "scribe notify no longer starts at logon (a running one stops at logoff)"
    return
}
$exe = Join-Path $PSScriptRoot 'scribe.exe'
if (-not (Test-Path $exe)) { throw "scribe.exe not found next to this script" }
# A hidden PowerShell keeps the console window of scribe.exe out of sight.
$command = "powershell.exe -NoProfile -WindowStyle Hidden -Command `"& '$exe' notify`""
Set-ItemProperty -Path $key -Name $name -Value $command
Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden `
    -ArgumentList '-NoProfile', '-Command', "& '$exe' notify"
Write-Host "scribe notify starts at logon and is running now"
