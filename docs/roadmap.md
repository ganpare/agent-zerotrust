# Roadmap

The project grows in three phases. Each phase is independently useful: the
system is worth running at the end of Phase 1, with no AI anywhere.

| Phase | Goal | Key tech | Exit criteria |
|---|---|---|---|
| 0 | Foundation | — | Design docs merged (this commit) |
| 1 | Auditable access | Warpgate + Tetragon | [Milestone 1](issues/001-auditable-ssh-access.md) — **COMPLETE** |
| 2 | Independent evaluation | Guardian AI + LLM | **COMPLETE**: auto-review, Telegram briefings, MCP approvals, LLM backends (Codex/DSH) |
| 3 | Automatic prevention | Policy engine + IPS | **CORE COMPLETE**: privileged broker, signed permission leases, deny→request→approve→redeem loop verified live |

## Phase 0 — Foundation

- Threat model ([threat-model.md](threat-model.md)) as the axis document
- Architecture ([architecture.md](architecture.md))
- This roadmap and the ready-to-file [Milestone 1 issue](issues/001-auditable-ssh-access.md)
- The repository starts **private**; going public is a deliberate gate,
  not an accident (see below)

## Phase 1 — Establish auditable SSH access

Goal: an AI agent does real work on the protected host over SSH, and
everything it does is provable afterwards — without trusting the agent.

Deliverables: `deploy/warpgate`, `deploy/tetragon`, `deploy/monitoring`,
`policies/network`, and the correlation design validated in practice.

Exit criteria: the acceptance checklist in
[issues/001-auditable-ssh-access.md](issues/001-auditable-ssh-access.md).

## Phase 2 — Guardian AI (optional layer)

- Input: the correlated evidence timeline (session → commands → kernel
  events) from Phase 1
- Output: risk score, narrative explanation, anomaly flags, alerts (IDS)
- Telegram adapter: IDS alerts with evidence context — and, later, the
  approval channel ([architecture.md](architecture.md) §8)
- MCP `request_approval`: advisory, agent-cooperative approval flow
  ([architecture.md](architecture.md) §8)
- Four-record briefing (Evidence / Claim / Assessment / Decision) as
  distinct, provenance-labeled records
  ([architecture.md](architecture.md) §8.6); the review function
  prototype — one-shot, single swappable backend, advisory-only — is
  implemented in `guardian/` (PR #2, merged) and verified by adversarial
  tests (hostile model output, provider failure, malicious claims)
- Constraints:
  - **Optional** — the Phase 1 floor keeps working without it (SR5)
  - Pluggable LLM backend: local GPU or hosted API
  - Never on the enforcement path
- Evaluation: replay recorded sessions — including red-team sessions —
  and measure detection quality against known ground truth

## Phase 3 — Policy engine + IPS

- Default-deny execution and egress for the agent user
- Tetragon enforcement actions as the blocking primitive (kill process,
  syscall override), with network policy as the second enforcement layer
- Policy verdict **"ask"**: human-in-the-loop gating between allow and
  deny — single-use, action-bound approval tokens and permission leases
  over the Telegram adapter; fail closed on timeout
  ([architecture.md](architecture.md) §8.7)
- Denial-driven requests: a policy denial carries a machine-readable
  reason pointing at `request_approval` — any error-handling agent can
  follow it, no special integration needed
  ([architecture.md](architecture.md) §8.1)
- Privileged broker as the enforcement/redemption keystone: denial IDs,
  signed grants/leases, atomic redemption — **design comparison
  (sudo / polkit / broker) before any implementation**
  ([proposals/privileged-broker-and-lease.md](proposals/privileged-broker-and-lease.md),
  [architecture.md](architecture.md) §8.8); land in observe/deny-only
  mode first
- Acceptance harness: the twelve attack-oriented validation scenarios
  from the [evidence–intent proposal](proposals/evidence-intent-approval.md),
  mapped to threat IDs
  in `tests/security/`
- Rollout: **detect-only → ask → enforce** — never straight to blocking
- Kill switch: revoke an agent's access without logging into the protected
  host

## Beyond the current roadmap

- More transports through Warpgate (HTTPS, databases)
- Local agents (Claude Code, Codex): observation plane without the
  bastion
- Multi-agent / multi-tenant operation

## Non-goals (v1)

- Protecting the agent's own runtime — that is Meta Sentinel's territory
- Defending against administrator identity compromise or kernel 0-days
  (see [threat-model.md](threat-model.md) §2 and §7)

## Going public — a gate, not an accident

The repository starts private. Flipping it public is a deliberate step
with this checklist:

- [ ] History audited: no secrets, no real hostnames / IPs / identities in
      commits or recordings
- [ ] Commit authorship uses a publishable identity (GitHub noreply email)
- [ ] Docs re-reviewed for accuracy against what was actually built
- [ ] Issue tracker ready for outside reports, including a security policy
      (contact + disclosure process)
- [ ] LICENSE choice confirmed
