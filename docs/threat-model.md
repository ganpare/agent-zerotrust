# Threat Model

Status: **draft v0.1** — this is the axis document of the repository.
Architecture, policies, and tests should all trace back to the threats and
requirements defined here. Expect revisions as Phase 1 produces findings.

## 1. What we protect (assets)

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Data on the protected host | Irreplaceable personal/project data |
| A2 | Credentials and secrets on the host | SSH keys, tokens, `.env` files, cloud credentials |
| A3 | The LAN behind the protected host | NAS, IoT, other machines — lateral movement targets |
| A4 | Compute resources (GPU/CUDA) | Abuse: cryptomining, unauthorized workloads |
| A5 | Audit evidence (recordings + event logs) | Its integrity *and* confidentiality are both security-critical |
| A6 | The gateway's own configuration | Warpgate/Tetragon config, policies, ACLs |

## 2. Adversary model

The primary threat is **not** a sci-fi "malicious AI". It is a
**legitimately authenticated but untrusted agent session**, because an
agent can:

- act on **injected instructions** — prompt injection via web pages,
  issues, or package READMEs it was asked to read;
- act on **hallucinated or stale assumptions** — wrong paths, wrong flags,
  destructive commands that look reasonable;
- execute **compromised tooling** — supply-chain: whatever it
  `pip`/`npm`-installs runs with the agent user's privileges;
- be **driven by a stolen credential** — a leaked SSH key or device
  identity is indistinguishable from the real agent at authentication
  time.

We therefore treat the authenticated agent identity the way an ISP treats
its customers: a paying, legitimate, **untrusted** user on the machine.

**Out of scope (v1):** attacks on the agent's own runtime (that is Meta
Sentinel's territory), physical access, kernel exploits / 0-days, and
compromise of the *administrator* identities (Tailscale/Warpgate admin,
monitoring host root) — those are trusted by definition in this version.

## 3. Entry points

| Entry point | Intended guard |
|---|---|
| SSH to the protected host | Warpgate only; direct `sshd` paths blocked at the network layer |
| Shell & tools of the agent user | Unprivileged user; execution/egress policy (Phase 3) |
| Outbound network from the agent user | Observed (Phase 1), default-deny (Phase 3) |
| LAN-internal services | Not reachable from the agent user (network policy) |

## 4. Threats

| ID | Threat | Assets | Primary mitigation (phase) |
|---|---|---|---|
| T1 | File deletion/modification outside task scope | A1 | Evidence + least privilege (1); execution policy (3) |
| T2 | Reading or exfiltrating credentials and secrets | A2 | Evidence (1); egress control (3); secret-aware alerting (2) |
| T3 | Lateral movement into the LAN | A3 | Network policy: agent user cannot reach LAN (1) |
| T4 | Unauthorized outbound channels (C2, exfiltration) | A1, A2 | Egress monitoring (1); default-deny egress (3) |
| T5 | Bypassing Warpgate via direct SSH | A5 | Tailscale ACL + `sshd` listen config (1) |
| T6 | Anti-forensics: tampering with recordings, logs, or policies | A5, A6 | Evidence stored off-host; agent has no path or credentials (1) |
| T7 | Resource abuse (e.g. GPU cryptomining) | A4 | Exec evidence (1); execution policy (3) |
| T8 | Persistence (cron, systemd units, shell rc files, `authorized_keys`) | A1, A6 | File/exec evidence (1); execution policy (3) |
| T9 | Evidence leakage — recordings and logs contain secrets | A2, A5 | Evidence store ACLs, encryption at rest, retention limits (1) |
| T10 | Approval-channel attack: spoofed or replayed approvals; agent requests approval for one action and performs another | A1, A2, A6 | Action-bound single-use short-TTL tokens; fail-closed timeout (3) |
| T11 | Approval fatigue: the human rubber-stamps requests, turning "ask" into silent allow | A1, A2 | Guardian pre-screening keeps volume low; approval patterns are evidence; escalation limits (3) |
| T12 | Adversarial claims: injection or social engineering aimed at the Guardian or the human via claim/briefing text | A1, A2, A6 | Claims are untrusted data (four-record model); fixed-template briefing; gateway-minted buttons; "what will run" comes from the enforcement record (2–3) |
| T13 | Broker compromise or grant/lease forgery — the redemption point is a new high-value target | A1, A2, A6 | Minimal hardened broker; offline-verifiable signed grants/leases; atomic local redemption ledger; funnel by DAC + Tetragon (3) |

## 5. Trust boundaries

```text
  (1) agent ↔ Tailscale        device identity
  (2) Tailscale ↔ Warpgate     the only open path to SSH (no direct sshd)
  (3) Warpgate ↔ target user   per-agent mapped, unprivileged user
  (4) userland ↔ kernel/eBPF   Tetragon observes from a ring the user cannot disable
  (5) protected host ↔         one-way evidence stream; the agent holds no
      monitoring host          credentials for the monitoring host
  (6) gateway ↔ human          approval channel (Telegram adapter,
      approver                 Phase 2–3): the approver's account
                               authenticates step-up decisions (SR8)
```

Boundary (4) is what makes the evidence *ground truth*: the monitored user
cannot turn Tetragon off, filter its output, or forge its events from
userland. Boundary (5) is what makes the evidence *survive* a compromised
session.

## 6. Security requirements

| ID | Requirement | Traces to |
|---|---|---|
| SR1 | All agent SSH access is mediated and recorded; direct paths are technically blocked | T5 |
| SR2 | Kernel-level ground truth (exec, file, network) exists for every session and is correlated to that session | T1, T2, T4, T7, T8 |
| SR3 | Evidence is append-only for the agent, stored off-host, unreachable from the protected host's agent identity | T6 |
| SR4 | Evidence is protected at rest (it may contain secrets); access to it is logged | T9 |
| SR5 | The security floor (SR1–SR3) keeps functioning with Guardian AI down | all |
| SR6 | The agent user cannot reach LAN-internal services | T3 |
| SR7 | The agent user cannot modify gateway, policy, or monitoring configuration | T6 |
| SR8 | Approvals bind to the exact action and the requesting agent identity; grants are single-use with a bounded TTL, leases are per-use-verified with expiry and count limits — both fail closed on expiry, mismatch, or channel loss | T10, T13 |
| SR9 | Every approval request and decision is an evidence record, and request volume stays low enough that approvals remain meaningful | T10, T11 |
| SR10 | Deterministic policy sets the review tier; the Guardian may only raise scrutiny, never lower it; model output structurally cannot carry grants, tiers, or decisions | T10, T12 |

SR5 is the project's fail-safe property and is deliberate: deterministic
access control is the floor; AI analysis is the enhancement. A user without
a GPU gets a working audited-access system, and a Guardian AI outage must
never widen the agent's privileges.

## 7. Residual risk (accepted in v1)

- A kernel-level compromise of the protected host defeats Tetragon — the
  observer and the observed share a ring. Mitigation is out-of-band
  alerting on *silence* (a host that stops emitting events is itself an
  incident).
- Compromise of an administrator identity (Tailscale/Warpgate admin,
  monitoring host root) is out of the model — administrators are trusted.
- Guardian AI false positives/negatives — acceptable precisely because it
  never holds the only line of defense (SR5).
- Session recording captures secrets typed by the agent; SR4 reduces but
  does not eliminate the retention risk.
- The approval channel (Phase 2–3) makes the approver's messaging account
  part of the security perimeter. Approvals stay scope-limited and
  action-bound (SR8), so a compromised approver account is bad but is not
  a root key; approval messages never carry secret values. A future
  auto-approver widens the perimeter again: it must run outside the
  acting agent's reach and decide only within policy-defined risk classes
  (architecture §8.3), or it becomes a privilege-escalation path.
- The Phase 3 broker is a new privileged component; its compromise
  equals root on the protected host. Minimal code, offline-verifiable
  signed grants/leases, and an atomic local ledger reduce but do not
  eliminate this — accepted because the alternatives (broader sudo,
  polkit sprawl) enlarge the privileged surface more than a small broker
  does. The comparison lives in
  [proposals/privileged-broker-and-lease.md](proposals/privileged-broker-and-lease.md).
