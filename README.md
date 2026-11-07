# agent-zerotrust

**Zero Trust Security Gateway for AI Agents**

Give AI agents real access to your machines — without trusting them.

`agent-zerotrust` is an open foundation for providing AI agents (Muse, Claude
Code, Codex, Hermes, ...) with **audited, constrained access to local
environments** — and for proving, after the fact, exactly what they did.

> **Status: design phase / PoC.** Nothing is deployed yet. The active
> milestone is [Milestone 1 — auditable SSH access](docs/issues/001-auditable-ssh-access.md).
> See the [roadmap](docs/roadmap.md) for where this is going.

## Why

AI agents increasingly get what is effectively interactive shell access to
development machines. The prevailing model is *trust the agent*: hand it an
SSH key and hope its behavior stays in scope.

Meta's [security approach for Muse](https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse)
guards the **agent's own execution environment** — an independent Sentinel
handles privilege control, the runtime is sandboxed, and eBPF restricts its
communications. That protects the agent.

This project protects the other side: **the machine the agent connects to.**
Your home server, with your data, your credentials, and your LAN behind it.

The premise is zero trust:

- An authenticated session is not a trusted session.
- Every action is mediated, recorded, and explainable.
- Evidence lives where the monitored principal cannot reach it.
- The security floor works **with no AI at all** — Guardian AI is an
  optional layer that adds semantic analysis on top, and the floor keeps
  working when it is down.

## Architecture (Phase 1 target)

```text
                AI agents
            ┌────┴─────────────┐
           Muse            Claude Code / Codex   (future: local agents)
            │
     Tailscale ── path restriction: only the bastion is reachable
            │
     ┌──────┴──────┐
     │   Warpgate  │  SSH bastion
     │             │  · per-agent identity & auth
     │             │  · full session recording & replay
     └──────┬──────┘
            │
┌───────────┴─────────────────── protected host ───────────────────────┐
│  Linux · `ai-muse` unprivileged user (GPU/CUDA available)             │
│  Tetragon (eBPF) ─ kernel-level ground truth:                        │
│      what was executed, which files were touched, where it connected  │
└───────────┬──────────────────────────────────────────────────────────┘
            │ one-way evidence stream (the agent cannot reach it)
┌───────────┴─────────────────── monitoring host ───────────────────────┐
│  evidence store (recordings + events)                                 │
│  Guardian AI (optional) ─ semantic analysis, anomaly detection,       │
│                          risk scoring                                 │
│  IDS ─ notify now          IPS ─ block (Phase 3, via Tetragon          │
│                               enforcement + network policy)            │
└───────────────────────────────────────────────────────────────────────┘
```

The key Phase 1 problem is **correlation**: what the terminal shows is not
what the kernel did. A single `python train.py` on the PTY can open a
hundred files and call out to the internet. Warpgate tells you *what the
agent typed*; Tetragon tells you *what actually happened*; correlating the
two makes the session auditable. See
[docs/architecture.md](docs/architecture.md).

## Design principles

1. **Evidence over impressions.** Auditability rests on kernel-level ground
   truth (eBPF), not on what the agent chose to print.
2. **AI-optional by design.** Access control, recording, and evidence work
   with zero AI. Guardian AI is an enhancement: deep behavioral analysis for
   those who can run it, never a dependency for those who cannot.
3. **Tamper-resistant evidence.** The monitored principal cannot turn off
   the monitors, edit recordings, or reach the evidence store.
4. **No bypass.** If Warpgate is the front door, there must be no back
   door — direct SSH paths are technically blocked, not just discouraged.
5. **Protect the evidence itself.** Session recordings can contain secrets;
   their confidentiality and retention are design requirements, not
   afterthoughts.

The full asset/adversary/requirement analysis is in
[docs/threat-model.md](docs/threat-model.md) — the axis document of this
repository.

## Roadmap

| Phase | Goal | Key tech | Exit criteria |
|---|---|---|---|
| 1 | Fully track what agents actually do | Warpgate + Tetragon | [Milestone 1](docs/issues/001-auditable-ssh-access.md) checklist |
| 2 | An independent AI evaluates the actions | Guardian AI + LLM | risk-scored real sessions, alerting |
| 3 | Automatically block dangerous actions | policy engine + IPS | default-deny exec/egress for the agent user |

Details: [docs/roadmap.md](docs/roadmap.md).

## Repository layout

```text
agent-zerotrust/
├── README.md
├── LICENSE                  Apache-2.0
├── docs/
│   ├── architecture.md      components, correlation, fail-safe behavior
│   ├── threat-model.md      assets, adversaries, threats, requirements
│   ├── roadmap.md           phases and exit criteria
│   └── issues/              ready-to-file milestone issues
├── deploy/
│   ├── warpgate/            bastion config, target/user mapping
│   ├── tetragon/            tracing policies (exec / file / network)
│   └── monitoring/          evidence pipeline, retention
├── guardian/               optional Guardian AI (consumes evidence, never enforces)
├── policies/
│   ├── network/             Tailscale ACLs, egress policy
│   └── execution/           execution policy (Phase 3)
└── tests/
    └── security/            attack-scenario scripts validating the threat model
```

## Related work

- [Meta: Security and safety for AI agents — our approach with Muse](https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse)
  — protects the agent's own runtime; `agent-zerotrust` protects the target.
- [Warpgate](https://warpgate.null.page/) — SSH bastion with session
  recording and replay.
- [Tetragon](https://tetragon.io/) — eBPF-based security observability and
  enforcement; runs on plain Linux hosts, no Kubernetes required.
- [Tailscale](https://tailscale.com/) — WireGuard mesh with ACLs, used to
  restrict the network path.

## License

[Apache-2.0](LICENSE)
