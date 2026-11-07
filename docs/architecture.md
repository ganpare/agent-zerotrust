# Architecture

Status: draft v0.1. Derived from [threat-model.md](threat-model.md) — every
component below exists to satisfy a security requirement (SR) there.

## 1. Overview

Two hosts, five planes:

```text
                          ┌──────────────────────┐
                          │      AI agents       │
                          │  Muse · others later │
                          └──────────┬───────────┘
                                     │
                        path plane: Tailscale (SR1, T5)
                                     │
                          ┌──────────┴───────────┐
                          │       Warpgate       │  access plane
                          │ SSH bastion, per-    │  (SR1)
                          │ agent auth, session  │
                          │ recording & replay   │
                          └──────────┬───────────┘
                                     │
   ┌───────────────── protected host ┴──────────────────┐
   │  isolation plane: unprivileged agent user (ai-muse) │
   │                                                     │
   │  observation plane: Tetragon (eBPF)                 │
   │  exec · file · network ground truth (SR2)           │
   └──────────────────────┬──────────────────────────────┘
                          │  one-way evidence stream (SR3)
   ┌──────────────────────┴──── monitoring host ─────────┐
   │  evidence plane:                                    │
   │  · evidence store (recordings + events) (SR3, SR4)  │
   │  · Guardian AI (optional) (SR5)                     │
   │  · IDS: notify now · IPS: block in Phase 3          │
   └─────────────────────────────────────────────────────┘
```

The protected host is where the agent works. The monitoring host is where
the proof lives. The agent holds no credentials for the monitoring host and
no network path to it — boundary (5) in the threat model.

## 2. Components

| Component | Plane | Role | SR |
|---|---|---|---|
| Tailscale | path | Restricts *how* the agent can reach the host at all; only Warpgate's port is reachable, direct `sshd` is not | SR1 |
| Warpgate | access | SSH bastion: per-agent identity, target/user mapping, full session recording and replay | SR1 |
| `ai-muse` user | isolation | Unprivileged mapped user on the protected host; GPU/CUDA available; no rights over gateway config | SR6, SR7 |
| Tetragon | observation | eBPF-based ground truth — exec, file operations, network connections — from a ring the user cannot disable | SR2 |
| Evidence pipeline | evidence | Ships recordings + events off-host, one-way; append-only for the agent | SR3 |
| Evidence store | evidence | Holds recordings and events; encrypted at rest; access logged; retention policy | SR4 |
| Guardian AI | analysis | *Optional.* Consumes the correlated evidence timeline; produces risk scores, anomaly reports, narrative explanation | SR5 |
| IDS / IPS | response | Phase 1–2: notify. Phase 3: block via Tetragon enforcement actions + network policy | — |

## 3. The core problem: correlation

What the PTY shows is not what the kernel did. A single `python train.py`
on the recorded terminal can open a hundred files and call out to the
internet, and neither the recording nor the agent's final summary will
show it.

**Design goal: every Tetragon event must be attributable to the Warpgate
session that caused it.**

Candidate mechanisms, to be validated in Phase 1 (likely a combination):

1. **Process-tree correlation** — exec events carry parent-PID chains; walk
   from the session's shell down. Robust for normal flows; needs care with
   daemons that detach.
2. **Per-session cgroup tagging** — run each session's processes in a
   cgroup tagged with the Warpgate session ID; Tetragon events carry cgroup
   IDs. Cleanest attribution, needs a session launcher hook.
3. **uid/sessionid fallback** — audit-style session identifiers as a
   coarse-grained backstop.

Correlation is the piece that makes the sum (Warpgate × Tetragon) more
valuable than either part, and it is the main unknown of Milestone 1.

## 4. Evidence plane

- Recordings (Warpgate) and events (Tetragon) land on the monitoring host.
  The stream is one-way; the agent user has no credentials for that host.
- Retention and at-rest protection are requirements from day one (SR4) —
  recordings can contain secrets.
- The monitoring host must alert on *silence*: a protected host that stops
  emitting events is itself an incident (kernel-level compromise is
  residual risk, but detectable by absence).

## 5. Fail-safe behavior

The system degrades to its floor, never below it:

| Component down | What still protects | What is lost |
|---|---|---|
| Guardian AI | Everything: auth, recording, evidence (SR5) | Semantic analysis, risk scores |
| Monitoring host | Local ring-buffer of events; access control unaffected | Off-host evidence freshness |
| Tetragon | Warpgate recording still runs; silence alert fires | Kernel ground truth |
| Warpgate | **No access path at all — fails closed** | Agent can't work (by design) |

## 6. Why this generalizes beyond Muse

- **Muse over SSH** uses the full stack (Warpgate + Tetragon + evidence).
- **Local agents** (Claude Code, Codex) skip the path/access planes — no
  Warpgate leg — but the observation plane (Tetragon policies scoped to
  their processes/users), the evidence schema, and Guardian AI apply
  unchanged.
- The event schema and policy format are agent-agnostic by design; this is
  what makes the project a *common foundation* rather than a Muse plugin.

## 7. Phase mapping

- **Phase 1** — components 1–6 (no AI anywhere): auditable access.
- **Phase 2** — add Guardian AI on the monitoring host, consuming the
  correlated timeline; IDS alerting.
- **Phase 3** — policy engine + IPS: default-deny execution/egress for the
  agent user; Tetragon enforcement actions as the blocking primitive;
  detect-only rollout before enforcement.
