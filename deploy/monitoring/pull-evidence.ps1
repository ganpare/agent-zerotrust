# Evidence pull — run on the monitoring host (evo Windows).
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
#   - Adjust $Remote / $RemoteSpool / $LocalRoot to match the deployment
#
# Schedule: Task Scheduler, e.g. every 15 minutes.
# Retention: evidence may contain secrets (SR4) — keep the local store
# on an encrypted volume, restrict NTFS access, and prune old snapshots.

$Remote = "evidence-collector@<PROTECTED_HOST_IP>"
$RemoteSpool = "/mnt/ssd2tb/agent-zerotrust/state/evidence"
$LocalRoot = "$env:USERPROFILE\agent-zerotrust-evidence"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"

New-Item -ItemType Directory -Force -Path "$LocalRoot\warpgate" | Out-Null
New-Item -ItemType Directory -Force -Path "$LocalRoot\tetragon" | Out-Null

# Warpgate session recordings + the Tetragon event spool
scp -r "${Remote}:${RemoteSpool}/warpgate" "$LocalRoot\warpgate\$Stamp"
scp -r "${Remote}:${RemoteSpool}/tetragon" "$LocalRoot\tetragon\$Stamp"

Write-Host "Pulled evidence snapshot $Stamp"
