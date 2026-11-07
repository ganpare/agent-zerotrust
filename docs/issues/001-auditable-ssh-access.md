# Issue #1 — Establish auditable SSH access for AI agents

> Ready-to-file text for the first milestone issue. Track it here until the
> repository accepts issues.

## Goal

An AI agent (Muse) performs real work on the protected host over SSH, and
everything it does is provable afterwards — without trusting the agent.

## Acceptance criteria

- [x] The agent can SSH **only** via Warpgate; a direct `sshd` connection
      under the agent's identity is refused (Tailscale ACL / listen config)
      — *validated end-to-end from a real second tailnet device
      (<TEST_DEVICE>): `:22` timed out (dropped), `:2222` reached
      warpgate; host-side iptables rule + `agent-zerotrust-firewall.service`;
      the tailnet ACL remains recommended defense-in-depth*
- [x] The full session is recorded in Warpgate and replayable
      — *`recordings_enable` on (it is a global parameter, not a setup
      flag); Terminal casts verified via the admin API and on disk*
- [x] Every command executed in the session has a matching Tetragon `exec`
      event, correlated to that session (process tree / cgroup)
      — *proven: `sshd → bash -c … → cat/curl` with full parent-PID
      ancestry (`tests/security/run-phase1.sh`)*
- [x] File opens and network connections by session processes are captured
      as Tetragon events — *canary secret read and outbound connect both
      captured by the UID-scoped policies*
- [x] Evidence (recordings + events) is stored off-host and is not writable
      or deletable by the agent user — *pull runs on the monitoring host
      (<MONITORING_HOST>) every 15 min via a read-only SFTP collector; warpgate DB +
      recording casts + rotated tetragon exports verified landing; agent
      cannot read or delete any of it (T6)*
- [x] Access can be revoked without logging into the protected host
      (kill switch) — *role revocation via the off-host admin API denies
      access immediately; restore re-enables it*

**Completed 2026-11-07.** Full deployment record and verification log:
[deploy/README.md](../deploy/README.md). Follow-ups (not blocking):
tailnet ACL application, Muse host onboarding, sshd password-auth
hardening.

## Tasks

1. Deploy Warpgate; map the agent identity to an unprivileged user
   (`ai-muse`)
2. Tailscale ACL: only Warpgate's port reachable from the agent; `sshd`
   not exposed directly
3. Install Tetragon on the protected host (plain Linux / systemd, no
   Kubernetes)
4. Write tracing policies: `exec`, file open, `connect` — scoped to the
   agent user
5. Implement session ↔ event correlation (process tree / cgroup tagging)
6. Ship evidence to the monitoring host (one-way stream)
7. Document the deployment under `deploy/` and validate it with the
   scenarios in `tests/security/`

## Out of scope

Any blocking — that is Phase 3. This milestone is access control plus
observability.

## References

- [threat-model.md](../threat-model.md) — SR1–SR3
- [architecture.md](../architecture.md) — §3, correlation
