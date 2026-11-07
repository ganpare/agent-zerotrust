# Architecture

Status: draft v0.1. Derived from [threat-model.md](threat-model.md) — every
component below exists to satisfy a security requirement (SR) there.

## 1. Overview

Two hosts, six planes:

```text
                          ┌──────────────────────┐
                          │      AI agents       │
                          │  Muse · others later │
                          └──────────┬───────────┘
                                     │
                        path plane: Tailscale (SR1, T5)
                                     │
                  ┌──────────────────┴──────────────────┐
                  │                                     │
        ┌─────────┴─────────┐                 ┌─────────┴─────────┐
        │      Warpgate     │  access plane   │   MCP Gateway     │  control plane
        │  SSH bastion      │  (SR1)          │   :8930           │  (SR8, SR9)
        │  recording        │                 │   approval +      │
        └─────────┬─────────┘                 │   worker dispatch │
                  │                           └─────────┬─────────┘
                  │                                     │
   ┌──────────────┴──── protected host ────────────────┴──────────────┐
   │  isolation plane: unprivileged agent user (ai-muse)               │
   │                                                                   │
   │  observation plane: Tetragon (eBPF)                               │
   │  exec · file · network ground truth (SR2)                         │
   │                                                                   │
   │  enforcement plane: privileged broker (signed leases)             │
   │  + Worker Gateway: codex / dsh / opencode / commandcode /         │
   │    vibe / agy → `ssh windows` for GPU work on the Windows host    │
   └──────────────────────┬────────────────────────────────────────────┘
                          │  one-way evidence stream (SR3)
   ┌──────────────────────┴──── monitoring host ────────────────────────┐
   │  evidence plane:                                                    │
   │  · evidence store (recordings + events) (SR3, SR4)                  │
   │  · Guardian AI (optional) (SR5)                                     │
   │  · IDS: notify now (Telegram) · IPS: OS-boundary allow (Phase 3)    │
   └─────────────────────────────────────────────────────────────────────┘
```

The protected host is where the agent works. The monitoring host is where
the proof lives. The agent holds no credentials for the monitoring host and
no network path to it — boundary (5) in the threat model.

### 1.1 The worker gateway (agent delegation)

The agent does not get extra credentials to reach other machines. Instead:

- **Muse → MCP Gateway (:8930)**: `dispatch_worker_task(agent, instruction,
  target, workdir)` asks a **local CLI agent** (codex, dsh, opencode,
  commandcode, vibe, agy) to do the work.
- **Worker → Windows**: the worker is instructed to operate on the Windows
  host **only through `ssh windows`** (owner's environment, RTX 4090).
  Mounts and additional Windows users are deliberately not used.
- **Every dispatch is**: safety-screened (credential reads, service stops,
  root wipes are blocked), audited (append-only log on the 22 TB evidence
  drive), and briefed to Telegram (start + completion).
- **SSH-only access**: the agent can also call the same gateway from inside
  its SSH session via `azt-worker`, so no MCP client is required.

### 1.2 Current IDS / IPS posture

| Control | Status |
|---|---|
| IDS: session review + Telegram briefing | **live** |
| IDS: privilege denial events + approval requests | **live** |
| IPS: `ai-muse` has no sudo (OS boundary) | **live** |
| IPS: privileged ops only via broker + signed lease | **live** |
| IPS: network egress default-deny | **not yet** (observed only) |
| IPS: Tetragon process kill / syscall block | **not yet** (Phase 3 follow-up) |

## 2. Components

| Component | Plane | Role | SR |
|---|---|---|---|
| Tailscale | path | Restricts *how* the agent can reach the host at all; only Warpgate's port is reachable, direct `sshd` is not | SR1 |
| Warpgate | access | SSH bastion: per-agent identity, target/user mapping, full session recording and replay | SR1 |
| `ai-muse` user | isolation | Unprivileged mapped user on the protected host; GPU/CUDA available; no rights over gateway config | SR6, SR7 |
| Tetragon | observation | eBPF-based ground truth — exec, file operations, network connections — from a ring the user cannot disable | SR2 |
| Evidence pipeline | evidence | Ships recordings + events off-host, one-way; append-only for the agent | SR3 |
| Evidence store | evidence | Holds recordings and events; encrypted at rest; access logged; retention policy | SR4 |
| Guardian AI | analysis | *Optional.* One-shot, advisory review of evidence vs. claim (§8.6); single swappable backend; may raise but never lower a review tier | SR5, SR10 |
| Approval service | response | *Phase 2–3.* Packages approval requests — proactive (MCP `request_approval`) or denial-driven (the policy's "ask" verdict) — routes them to a pluggable decider over a channel adapter (Telegram first), issues single-use, action-bound tokens and permission leases (§8.2, §8.7) | SR8, SR9 |
| Privileged broker | enforcement | *Phase 3, design stage.* The only privileged door on the protected host: mints denial IDs, verifies signed grants/leases, redeems atomically, executes the bound action, emits evidence (§8.8; sudo/polkit comparison pending) | SR8, SR10 |
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

A structured denial can only be minted by a **controlled enforcement
point** (Phase 3: the privileged broker for execution, the egress gate
for network). Generic OS failures — a plain `EPERM`, a stock sudo
refusal, or a Tetragon observation — carry no requestable denial ID;
requests that reference them are marked **unverified** and can never
route to an ALLOW-tier outcome.

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
- **Single-use tokens and permission leases.** No replay; no blanket
  approvals. A **lease** (§8.7) permits narrow, bounded repeat use for
  legitimate repeated work — and every individual use is still verified
  and recorded at redemption.
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

### 8.6 The four-record model (adopted)

Every approval case keeps four records with distinct provenance,
timestamps, and immutability expectations:

1. **Evidence** — observed facts from the enforcement/recording side
   (Warpgate metadata and recordings, Tetragon events, denial records).
   Answers *what was observed*. Off-host; collection gaps are reported,
   never interpreted as safety.
2. **Claim** — the acting agent's untrusted explanation: purpose,
   justification, expected effect, alternatives. Answers *what is
   asserted*, never what is proven. Versioned: a clarification produces
   a new claim version without altering the original.
3. **Assessment** — the Guardian's advisory comparison of evidence and
   claim: consistency, risks, alternatives, uncertainties — referencing
   the exact evidence and claim versions used. Advisory only; never a
   permission.
4. **Decision** — the authoritative verdict of the human decider (or a
   future strictly scoped auto-decider), plus grant/lease/redemption
   history.

Rules: append-only, nothing overwritten; claims are untrusted data and
never instructions — to the Guardian or to the human briefing; the
briefing renders the four records as distinct labeled fields, and the
"what will actually run" line comes from the enforcement record, not the
claim. A prototype of the review function (one-shot, single swappable
backend, advisory-only) is implemented in `guardian/` (PR #2, merged) and
verified by adversarial tests: hostile model output, provider failure,
and malicious claims cannot alter tiers, force grants, or block human
review.

### 8.7 Permission leases

Per-operation approval does not scale to legitimate repeated work;
blanket grants are unsafe. The middle instrument is the **lease**:

```text
 lease = agent principal + operation class + narrow scope
       + expiry (+ optional max uses)
```

- Example: "restart the `training-web` service, up to 10 times, within
  2 hours."
- A lease redeems like a token, but repeatedly: **every individual use
  is verified by the broker** (binding recheck, §8.2) and recorded as
  its own evidence event. Request ID → Lease ID → operation events are
  separately traceable — for approval auditing and later incident
  investigation.
- Expiry, use-count exhaustion, revocation, or any binding mismatch ends
  the lease's validity; a changed target or operation requires a new
  approval, never a reuse.
- Leases never widen: anything outside the leased operation class keeps
  its deterministic tier.

### 8.8 Enforcement point and the privileged broker (design stage)

Phase 3's "ask" verdict needs a controlled enforcement/redemption point
on the protected host — generic `EPERM` can neither mint denial IDs nor
redeem grants. Leading design (pending the sudo/polkit comparison, see
[proposals/privileged-broker-and-lease.md](proposals/privileged-broker-and-lease.md)):

- The agent user has **no sudo**; the broker is the only privileged door
  for approvable classes (the funnel is enforced by DAC plus Tetragon
  static denies).
- The broker mints **denial IDs** with the exact action spec; verifies
  **signed grants/leases** offline (pinned public key); redeems
  **atomically** (local append-only ledger, unique-ID constraint under a
  lock — a concurrent double-redeem fails exactly one); executes exactly
  the bound action; and emits redemption + post-exec evidence.
- **Rollout:** land the broker in observe/deny-only mode (no
  redemption), then enable grants and leases — the same
  detect-before-enforce discipline as everything else.
