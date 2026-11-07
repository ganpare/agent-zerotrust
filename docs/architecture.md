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
| Approval service | response | *Phase 2–3.* Packages approval requests — proactive (MCP `request_approval`) or denial-driven (the policy's "ask" verdict) — routes them to a pluggable decider over a channel adapter (Telegram first), issues single-use, action-bound tokens via the async protocol (§8) | SR8, SR9 |
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
  correlated timeline; IDS alerting over the Telegram adapter; advisory
  MCP `request_approval` (§8).
- **Phase 3** — policy engine + IPS: default-deny execution/egress for the
  agent user; Tetragon enforcement actions as the blocking primitive; the
  "ask" verdict adds human-in-the-loop gating (§8) between allow and deny;
  detect-only rollout before enforcement.

## 8. Human-in-the-loop approvals (design note)

Status: **design stage** — the MCP surface and the async protocol are
decided; open questions at the end.

Detection and blocking are the two ends of a ladder. Between them sits
**asking the human**.

### 8.1 Trigger paths

```text
 (a) proactive      the agent anticipates: "the next step needs sudo /
                    deletes a directory / opens a new destination"
                    → calls request_approval first

 (b) denial-driven  the agent tries; policy denies with a machine-readable
                    reason, e.g.
                    "blocked by policy: action requires approval —
                     call request_approval(action, justification), then
                     retry"
                    → agent asks, then retries the exact action

 (b) is the universal one: it needs zero agent-side policy knowledge —
     the denial itself is the integration surface, so any error-handling
     agent can follow it. (a) remains a nicety for well-behaved agents.
```

### 8.2 Async approval protocol

MCP tool calls are request/response (JSON-RPC over stdio or HTTP). A
server may in principle hold a call open — there is even a
progress-notification mechanism — but client timeouts vary, and a human
may answer in minutes or hours. Holding an agent's tool call open for a
human-scale wait is fragile. So the protocol is **async**:

```text
 request_approval(action, justification)
   ─▶ returns immediately:
      {status: pending, request_id, expires_at}

 ... the human approves whenever they see it ...
      (request TTL is human-scale: hours, configurable)

 agent:  poll get_approval(request_id)   ← each poll is a normal call
      or simply retry the action         ← the natural agent behavior

 on grant ─▶ single-use token, bound to (agent identity, exact action),
             redeemable within the grant TTL (bounded, e.g. 1 h)
             → the retry succeeds; anything else stays denied

 deny / request TTL expired / channel loss ─▶ fail closed
```

Two distinct TTLs, by design:

- **Request TTL** — how long a request stays open. Human-scale (hours),
  because approvals arrive whenever the human gets to them.
- **Grant TTL** — how long a granted token stays redeemable. Bounded and
  short, because it gates live execution.

A late approval is therefore harmless: the request simply stays pending
until the human answers, and the agent redeems the grant by retrying —
in this session or a later one, since the token binds to the agent
identity, not to the session that asked.

### 8.3 Key properties

- **Approval binding.** The human approves *the gateway's view of the
  action*, not the agent's description of it. A token unlocks exactly the
  approved action for the requesting agent — nothing else. This is why
  *enforced* approvals need Phase 1 correlation and Phase 3 enforcement;
  before that, MCP approval is advisory (agent-cooperative) only.
- **Fail closed.** Deny, request-TTL expiry, channel loss — all mean
  denied.
- **Single-use tokens.** No replay. No blanket approvals — unless
  explicitly scoped (e.g. "allow this destination for 1 h").
- **No secrets in the channel.** The briefing carries actions and
  context, never secret values — Telegram is third-party infrastructure.
- **Telegram is an adapter, not the design.** The channel interface stays
  generic; Telegram is the first implementation (push + inline buttons).
- **Approvals are evidence.** Every request and decision is a record in
  the evidence store.
- **Pluggable decider.** The decision-maker behind a request is an
  interface: **human** (the default, and the only decider initially) or,
  later, an authorized auto-approver on the guardian side. Separation of
  authority applies to the latter: it runs on the monitoring host —
  outside the acting agent's reach — may decide only within
  policy-defined risk classes, and every grant it makes is logged
  evidence. Auto-approval is opt-in per risk class; everything else
  stays human-only.

### 8.4 Phase placement

- **Phase 2** — Telegram as the IDS alert channel; proactive, advisory
  `request_approval` (no enforcement yet).
- **Phase 3** — the policy verdict **"ask"**: denial-driven, enforced
  gating; retry-with-token redemption.

Rollout ladder: **detect-only → ask → enforce.**

### 8.5 Open questions

- Which risk classes may a future auto-approver decide alone, and which
  stay human-only?
- Do non-MCP agents need a CLI fallback (`azt request-approval ...`)?
- How does a granted-but-unredeemed token surface in the evidence store —
  request, grant, and redemption should be three distinct records.
