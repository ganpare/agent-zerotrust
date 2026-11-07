# Phase 1 deployment — two-machine layout

Milestone: [docs/issues/001-auditable-ssh-access.md](../docs/issues/001-auditable-ssh-access.md)

## Topology

| Role | Host | Tailscale | Runs |
|---|---|---|---|
| Protected host (stage 1) | `<PROTECTED_HOST>` (Ubuntu 24.04, kernel 6.17) | `<PROTECTED_HOST_IP>` | sshd, Warpgate (Docker), Tetragon (Docker, privileged), evidence spool |
| Protected host (stage 2, later) | `<MONITORING_HOST>` (Windows) | `<MONITORING_HOST_IP>` | Warpgate target + recording; observation via Sysmon/Event Auditing (**Tetragon is Linux-only**) |
| Monitoring host (interim) | `<MONITORING_HOST>` | `<MONITORING_HOST_IP>` | evidence store; **pulls** from the protected host |
| Evidence store (stage 2 candidate) | `<NAS>` (NAS) | `<NAS_IP>` | once BOTH machines are protected hosts, the store must move to a third machine the agent cannot reach |

**Rule: a protected host cannot host the evidence store.** The store must
be outside the reach of the acting agent (SR3) — and once Muse works on
both machines, neither qualifies. The Synology is the natural stage-2
store; until <MONITORING_HOST> becomes a protected host, it serves as the interim
monitoring host.

## Deployment status (2026-11-07) — protected host DONE, verified

- [x] `ai-muse` unprivileged OS user created (uid 1001, no sudo, no
      password); Warpgate's client public key in its `authorized_keys`
- [x] Warpgate v0.30.4 (Docker, non-root, host network): SSH on
      `<PROTECTED_HOST_IP>:2222`, admin UI on `:8888`, role `ai-muse`, user
      `muse` (public-key), target `<PROTECTED_HOST>-local` → `127.0.0.1:22` as
      `ai-muse`; session recording to SQLite in `deploy/warpgate/state/db`
- [x] Tetragon v1.8.0 (Docker, privileged, `pid: host`, BTF mount):
      default exec events + UID-scoped tracing policies
      (`cred.uid.val` kernel-side filter → agent only, low noise);
      events exported as JSONL to `deploy/tetragon/state/events/`
- [x] **Correlation verified**: a session via
      `ssh muse:<PROTECTED_HOST>-local@<PROTECTED_HOST_IP>:2222` produced the full chain
      in the Tetragon stream — `sshd → bash -c "echo CORR-… && cat
      /etc/passwd && curl …" → cat / curl` — every process with parent
      PID linkage, uid, binary, and full arguments; the file read of
      `/etc/passwd` and the outbound connect were captured by the
      policies
- [x] 9 sessions recorded in the Warpgate DB (7 muse, 2 admin)

### Lessons learned (see the compose files and policies for the result)

- Warpgate `unattended-setup` requires `--data-path` and `--http-port`;
  `--listen-address` binds all listeners; users/roles/targets live in the
  DB and are managed via the admin API (`/@warpgate/api/auth/login` →
  cookie → `/@warpgate/admin/api/…`), not the YAML
- Warpgate authenticates to SSH targets with **its own generated client
  keys** (`warpgate client-keys`); the target's `authorized_keys` must
  contain that public key
- Tetragon does not print events to stdout; use
  `--export-filename` (JSONL) — this file doubles as the
  evidence-pipeline pickup point
- Tetragon kprobe policies can filter by **current task UID in the
  kernel** (`data: source: current_task, resolve: cred.uid.val` +
  `matchData`) — essential on a busy host (100 MB/s → agent-scoped
  trickle)
- The official `security_file_permission` policy pattern requires
  explicit `args` type declarations (`file`, `int`); a wrong `matchArgs`
  index aborts the daemon at startup

## Remaining for Milestone 1 (user actions)

- [ ] **Full T5 validation from a second tailnet device** (any device
      except <MONITORING_HOST>): `ssh -p 22 <PROTECTED_HOST_IP>` must FAIL,
      `ssh -p 2222` must reach warpgate
- [ ] **Tailscale ACL** (admin console): apply
      [policies/network/tailscale-acl.draft.hujson](../policies/network/tailscale-acl.draft.hujson)
      — device tags, agent → `:2222` only; the host-side nftables block
      is already active, the ACL adds the tailnet-level layer
- [ ] Muse's host joins the tailnet (`tag:agent-muse`) and receives
      `deploy/warpgate/state/muse-client-key` (transfer securely)
- [ ] Evidence pull on <MONITORING_HOST>: transfer
      `deploy/warpgate/state/evidence-collector-key` to <MONITORING_HOST>, then
      schedule [deploy/monitoring/pull-evidence.ps1](monitoring/pull-evidence.ps1)
- [ ] Verify a session recording replays in the warpgate admin UI
      (`https://<PROTECTED_HOST_IP>:8888/@warpgate/admin` → Recordings)

## Host-side controls already in place (verified)

- [x] **Direct-SSH bypass blocked at the host**: iptables/nftables rule
      drops `:22` arriving over `tailscale0` except <MONITORING_HOST>
      (<MONITORING_HOST_IP>); persisted via `agent-zerotrust-firewall.service`
      (`/usr/local/sbin/azt-firewall.sh`). Remove with the iptables -D
      command in that script's comment. Admin LAN SSH (<LAN_IP>)
      is unaffected; warpgate → `127.0.0.1:22` is unaffected.
- [x] **Evidence collector**: `evidence-collector` user (read-only
      SFTP via `ForceCommand internal-sftp -R`, no TTY/forwarding);
      spool dirs group-readable by `evidence` only — `ai-muse` cannot
      traverse them (SR3)
- [x] **Local acceptance tests**: `tests/security/run-phase1.sh` —
      8/8 PASS (SR2 correlation + ancestry, T2 canary read captured,
      T4 connect captured, T6 evidence unreadable/undeletable,
      collector read-only); T5 rule verified active via privileged
      check

## Hardening notes (not blocking Milestone 1)

- sshd has `PasswordAuthentication yes` globally. With the TS bypass
  block, exposure is LAN-only — consider disabling password auth after
  confirming no one needs it.
- The canary fixture `/home/ai-muse/canary-secret.txt` is a permanent
  T2 test fixture; it contains no real secret.
