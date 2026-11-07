# Evidence pull — run on the monitoring host (<MONITORING_HOST>, interim).
#
# Pull model: the monitoring host initiates every transfer; the protected
# host holds NO monitoring-host credentials (SR3).
#
# Uses the SYSTEM32 OpenSSH client explicitly — other scp.exe builds on
# this machine (e.g. the Kaisha one earlier in PATH) emit
# "protocol error: mtime.sec not present" against the read-only SFTP.
#
# Tetragon events are pulled INCREMENTALLY by filename: rotated export
# files are immutable once closed (rotation: 15m / 100MB), so anything
# new by name ships exactly once. The currently-open file is skipped; it
# ships when it rotates.
#
# Warpgate evidence (SQLite DB + session recording casts) is small and
# always-changing — pulled fresh every run. A torn WAL snapshot is
# possible while sessions run; use `sqlite3 .backup` host-side for
# forensic-grade copies later.

$ErrorActionPreference = "Continue"

$Remote  = "evidence-collector@<PROTECTED_HOST_IP>"
$Spool   = "/mnt/ssd2tb/projects/Zero-trust/deploy"
$KeyPath = "$env:USERPROFILE\agent-zerotrust\evidence-collector-key"
$LocalRoot = "$env:USERPROFILE\agent-zerotrust-evidence"
$SshDir  = "C:\Windows\System32\OpenSSH"
$Sftp = Join-Path $SshDir "sftp.exe"
$Stamp  = Get-Date -Format "yyyyMMdd-HHmmss"

New-Item -ItemType Directory -Force -Path "$LocalRoot\warpgate" | Out-Null
New-Item -ItemType Directory -Force -Path "$LocalRoot\tetragon" | Out-Null

function Invoke-Sftp([string[]]$Commands) {
    $batch = Join-Path $env:TEMP "azt-sftp-batch.txt"
    $Commands | Out-File -FilePath $batch -Encoding ascii
    & $Sftp -i $KeyPath -o StrictHostKeyChecking=accept-new -b $batch $Remote
    return $LASTEXITCODE
}

function Get-RemoteListing([string]$RemoteDir) {
    $batch = Join-Path $env:TEMP "azt-sftp-ls.txt"
    "ls -l $RemoteDir" | Out-File $batch -Encoding ascii
    (& $Sftp -i $KeyPath -o StrictHostKeyChecking=accept-new -b $batch $Remote) |
        Where-Object { $_ -match '^[d-]' }
}

# ---------- Tetragon events: incremental by filename ----------
$TgLocal = "$LocalRoot\tetragon"
$listing = Get-RemoteListing "$Spool/tetragon/state/events"
$newFiles = @()
foreach ($line in $listing) {
    $parts = $line -split '\s+'
    if ($parts.Count -lt 9) { continue }
    # sftp ls -l prints full paths — reduce to the file name
    $name = Split-Path -Leaf $parts[-1]
    if ($name -eq "tetragon.json") { continue }   # currently open — ships on rotation
    if (-not (Test-Path (Join-Path $TgLocal $name))) { $newFiles += $name }
}
if ($newFiles.Count -gt 0) {
    Write-Host "tetragon: pulling $($newFiles.Count) new file(s)"
    $cmds = @("lcd $($TgLocal -replace '\\','/')")
    foreach ($f in $newFiles) { $cmds += "get $Spool/tetragon/state/events/$f" }
    Invoke-Sftp $cmds | Out-Null
} else {
    Write-Host "tetragon: no new rotated files"
}

# ---------- Warpgate: DB + session recordings (fresh every run) ----------
$WgStamp = "$LocalRoot\warpgate\$Stamp"
New-Item -ItemType Directory -Force -Path $WgStamp | Out-Null
Write-Host "warpgate: pulling DB + recordings"
$cmds = @(
    "lcd $($WgStamp -replace '\\','/')",
    "get -r $Spool/warpgate/state/db",
    "get -r $Spool/warpgate/state/recordings"
)
Invoke-Sftp $cmds | Out-Null

Write-Host "Pulled evidence snapshot $Stamp"
