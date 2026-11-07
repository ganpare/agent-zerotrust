# Phase 1 deployment — two-machine layout

Milestone: [docs/issues/001-auditable-ssh-access.md](../docs/issues/001-auditable-ssh-access.md)

## Topology

| Role | Host | Tailscale | Runs |
|---|---|---|---|
| Protected host | `<PROTECTED_HOST>` (Ubuntu 24.04, kernel 6.17, BTF ✓) | `<PROTECTED_HOST_IP>` | sshd, Warpgate (Docker), Tetragon (Docker, privileged), evidence spool |
| Monitoring host | evo Windows (Tailscale name TBD) | TBD | evidence store; **pulls** from the protected host |

Deployment vehicle: the host's Docker daemon — no sudo needed from the
agent session. Tetragon runs as a **privileged** container because
loading and attaching BPF programs requires it; that is inherent to
eBPF, not an optional hardening choice.

## Sequence

1. **Agent user (privileged one-shot)** — create the unprivileged
   `ai-muse` user that Warpgate maps the agent onto. Executed via a
   one-shot privileged container (`useradd`); marked privileged because
   it changes host state.
2. **Warpgate** — [deploy/warpgate/docker-compose.yml](warpgate/docker-compose.yml);
   `unattended-setup` inside the container; SSH listener bound to the
   **Tailscale IP only**; role `ai-muse`; user `muse` with public-key
   auth; SSH target `127.0.0.1:22` mapped to `ai-muse`; session
   recording enabled.
3. **Tetragon** — [deploy/tetragon/docker-compose.yml](tetragon/docker-compose.yml)
   (privileged, `pid: host`, BTF mount, policy dir mount). Process-exec
   events are emitted by default; the two tracing policies in
   `deploy/tetragon/policies/` add sensitive-file opens and outbound
   connects.
4. **Evidence spool** — a root-only directory holding Warpgate
   recordings and the Tetragon event stream. The agent user can neither
   read nor delete it (SR3).
5. **Monitoring pull** — evo Windows runs
   [deploy/monitoring/pull-evidence.ps1](monitoring/pull-evidence.ps1)
   on a schedule. Pull model: the protected host holds **no**
   monitoring-host credentials.
6. **Tailscale ACL** — draft in
   [policies/network/tailscale-acl.draft.hujson](../policies/network/tailscale-acl.draft.hujson):
   the agent device may reach only `2222` (Warpgate); direct `22` is
   denied to it. **Review against the current tailnet ACL before
   applying** — the tailnet has other devices and flows that must not
   break.
7. **Validation** — run the `tests/security/` scenarios:
   - direct-SSH bypass attempt must fail (T5)
   - reading a planted secret must show up in the evidence (T2)
   - every session command must have a matching Tetragon exec event,
     correlated by process ancestry (SR2)

## Correlation (the Phase 1 core problem)

Warpgate session → PTY → shell PID. Tetragon exec events carry the full
process tree with host PIDs (`pid: host`), so the join key is process
ancestry + timestamp window + the fixed OS user (`ai-muse`), with cgroup
IDs as the second candidate (architecture §3). Validation step 7 is
where this join is proven before anything else is built on top of it.

## Open items

- [ ] Tailscale identity of evo Windows (monitoring host)
- [ ] How Muse connects — tailnet device (tag it `tag:agent-muse`), LAN,
      or public? Determines Warpgate's bind address and the ACL shape
- [ ] Current tailnet ACL review before applying the draft
- [ ] sshd: restrict direct `22` to admin sources once the ACL is in
      place — until then, direct SSH remains possible and **Milestone 1
      is not met**
- [ ] Verify Warpgate's `unattended-setup` flags and SSH-target
      user-mapping options against the installed version
