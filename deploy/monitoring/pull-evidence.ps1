# Evidence pull — run on the monitoring host (<MONITORING_HOST>, interim).
#
# Pull model: the monitoring host initiates every transfer; the protected
# host holds NO monitoring-host credentials (SR3). Uses the Windows
# OpenSSH client (ssh.exe/scp.exe, present on Windows 10+).
#
# Prereqs:
#   - Tailscale up on this machine
#   - SSH key for the dedicated `evidence-collector` user on <PROTECTED_HOST>
#     (read-only access to the evidence spool — a separate identity,
#     NOT ai-muse and NOT an admin)
#
# NOTE on the Warpgate DB: recordings live in SQLite (db.sqlite3 + WAL).
# Pulling a live WAL can yield a torn snapshot — for the PoC, pull while
# sessions are idle, or use `sqlite3 .backup` on the host side later.

$Remote = "evidence-collector@<PROTECTED_HOST_IP>"
$RepoRoot = "/mnt/ssd2tb/projects/Zero-trust/deploy"   # spool location on <PROTECTED_HOST>
$LocalRoot = "$env:USERPROFILE\agent-zerotrust-evidence"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"

New-Item -ItemType Directory -Force -Path "$LocalRoot\warpgate" | Out-Null
New-Item -ItemType Directory -Force -Path "$LocalRoot\tetragon" | Out-Null

# Warpgate session recordings (SQLite DB) and the Tetragon event stream (JSONL)
scp -r "${Remote}:${RepoRoot}/warpgate/state/db" "$LocalRoot\warpgate\$Stamp"
scp -r "${Remote}:${RepoRoot}/tetragon/state/events" "$LocalRoot\tetragon\$Stamp"

Write-Host "Pulled evidence snapshot $Stamp"
