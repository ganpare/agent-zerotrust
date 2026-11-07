# deploy/monitoring

The evidence plane (SR3, SR4): Warpgate recordings and the Tetragon event
stream land in a root-only spool on the protected host, and the
monitoring host **pulls** them on a schedule.

**Pull model, on purpose.** The protected host holds no
monitoring-host credentials — the monitoring host initiates every
transfer (architecture §4, boundary 5). A compromised agent session
therefore has nothing to steal and nowhere to push.

- Runner: [pull-evidence.ps1](pull-evidence.ps1) via Windows Task
  Scheduler (e.g. every 15 minutes)
- Transport: Tailscale + SSH (`scp`), key held by the monitoring host
  for a dedicated read-only `evidence-collector` identity on the
  protected host — separate from both `ai-muse` and admin
- Confidentiality: evidence may contain secrets (SR4) — encrypted
  volume on the monitoring host, restricted access, retention pruning
- Future (Phase 2+): stream events live instead of snapshotting; the
  Guardian and the approval service consume the same store

Lands in Phase 1 — see the runbook: [deploy/README.md](../README.md).
