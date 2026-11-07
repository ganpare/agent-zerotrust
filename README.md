# agent-zerotrust

**English** | [日本語](README.ja.md)

**Zero Trust Security Gateway for AI Agents**

Give AI agents real access to your machines — without trusting them.

`agent-zerotrust` is an open foundation for providing AI agents (Muse and
others) with **audited, constrained access to local environments** — and for
proving, after the fact, exactly what they did. Beyond SSH, it can *delegate*
work to local CLI agents (Codex, DSH, OpenCode, Command Code, Mistral Vibe,
Antigravity) without ever handing the remote agent their credentials.

> **Status: deployed and running.** Phase 1 (auditable SSH access) and
> Phase 2 (auto-review, Telegram briefings, MCP approvals, LLM backends) are
> complete; Phase 3 (privileged broker + signed permission leases) is core
> complete. See [deploy/README.md](deploy/README.md) for the live deployment
> record and [docs/roadmap.md](docs/roadmap.md) for what remains.

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

## Architecture

```mermaid
flowchart TB
    subgraph agents["AI Agents"]
        muse["Muse<br/><i>remote · SSH + MCP</i>"]
        local["Claude Code / Codex<br/><i>future: local agents</i>"]
    end

    subgraph tailnet["Tailscale · path restriction"]
        acl["ACL: agent → :22, :8930 only"]
    end

    subgraph bastion["Warpgate · SSH bastion"]
        wg["per-agent identity & auth<br/>full session recording & replay"]
    end

    subgraph protected["Protected host · Linux"]
        user["<code>ai-muse</code><br/>unprivileged · no sudo"]
        tg["<b>Tetragon (eBPF)</b><br/>kernel-level ground truth<br/>exec · file · network"]
        broker["<b>Privileged broker</b><br/>the only privileged door<br/>verifies signed leases"]
    end

    subgraph gateway["Gateway services"]
        mcp["<b>MCP Gateway (:8930)</b><br/>approval + worker dispatch"]
        watcher["Session watcher<br/>auto-review + briefing"]
        workers["<b>Worker Gateway</b><br/>codex · dsh · opencode<br/>commandcode · vibe · agy"]
    end

    subgraph windows["Windows host (GPU)"]
        win["RTX 4090 · <code>conta</code> env<br/><i>reached via ssh windows</i>"]
    end

    subgraph monitoring["Monitoring host"]
        store[("Evidence store<br/>recordings + events")]
        guardian["Guardian AI <i>(optional)</i><br/>evidence vs claim<br/>risk scoring"]
        ids["IDS · notify"]
    end

    human(["Human owner<br/>Telegram · admin UI"])

    muse -->|"ssh"| acl
    local -.->|"future"| acl
    acl -->|"only :22"| wg
    acl -->|"only :8930"| mcp
    wg -->|"as ai-muse"| user
    user -->|"every syscall"| tg
    user -->|"azt-broker"| broker
    user -->|"azt-worker / MCP"| mcp
    mcp -->|"dispatch_task"| workers
    workers -->|"ssh windows"| win
    tg -->|"one-way evidence"| store
    broker -->|"lease redemption"| store
    store --> guardian
    guardian --> ids
    watcher --> guardian
    watcher -->|"briefing"| human
    mcp -->|"approval request"| human
    human -->|"✅ / 🚫"| mcp
    mcp -->|"signed lease"| broker

    classDef agent fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    classDef bastionBox fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef hostBox fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    classDef controlBox fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef monBox fill:#eceff1,stroke:#546e7a,stroke-width:2px
    classDef humanBox fill:#fffde7,stroke:#fbc02d,stroke-width:2px
    classDef winBox fill:#e0f7fa,stroke:#00838f,stroke-width:2px

    class muse,local agent
    class acl,wg bastionBox
    class user,tg,broker hostBox
    class mcp,watcher,workers controlBox
    class store,guardian,ids monBox
    class human humanBox
    class win winBox
```

**The key problem is correlation**: what the terminal shows is not what the kernel did. Warpgate tells you *what the agent typed*; Tetragon tells you *what actually happened*; correlating the two makes the session auditable.

**The approval loop** closes the other direction: a denied privileged operation carries a machine-readable denial ID → the agent requests approval via MCP → the human taps on Telegram → a signed, bounded lease is minted → the broker verifies and redeems it, executing exactly the bound action.

**The worker gateway** extends the agent's reach without giving it credentials: the agent asks the MCP Gateway to *dispatch a task* to a local CLI agent (codex, dsh, opencode, commandcode, vibe, agy). The worker runs under the owner's environment, and Windows work is reached through `ssh windows` — never through mounts or extra Windows users. Every dispatch is safety-screened, audited, and briefed to Telegram.

**Current IDS/IPS posture**: IDS is live (session review + Telegram briefings). IPS is enforced as *allow-by-default at the OS boundary* (no sudo for `ai-muse`, broker-mediated privileged ops, network observed but not default-denied). Default-deny egress and Tetragon enforcement remain Phase 3 follow-ups.

See [docs/architecture.md](docs/architecture.md) for the full detail.

## Design principles

1. **Evidence over impressions.** Auditability rests on kernel-level ground
   truth (eBPF), not on what the agent chose to print.
2. **AI-optional by design.** Access control, recording, and evidence work
   with zero AI. Guardian AI is an enhancement: deep behavioral analysis for
   those who can run it, never a dependency for those who cannot.
3. **Tamper-resistant evidence.** The monitored principal cannot turn off
   the monitors, edit recordings, or reach the evidence store.
4. **No bypass.** If Warpgate and the MCP Gateway are the front doors,
   there must be no back door — direct SSH paths are technically blocked
   (sshd is LAN/loopback only; the tailnet's port 22 *is* Warpgate), not just
   discouraged.
5. **Protect the evidence itself.** Session recordings can contain secrets;
   their confidentiality and retention are design requirements, not
   afterthoughts.

The full asset/adversary/requirement analysis is in
[docs/threat-model.md](docs/threat-model.md) — the axis document of this
repository.

## Roadmap

| Phase | Goal | Key tech | Status |
|---|---|---|---|
| 1 | Fully track what agents actually do | Warpgate + Tetragon | **complete** — [Milestone 1](docs/issues/001-auditable-ssh-access.md) |
| 2 | An independent AI evaluates the actions | Guardian AI + LLM | **complete** — auto-review, Telegram, MCP approvals, Codex/DSH backends |
| 3 | Automatically block dangerous actions | policy engine + IPS | **core complete** — privileged broker + signed leases; egress default-deny remains |

Details: [docs/roadmap.md](docs/roadmap.md).

Between *detect* and *block* there is a middle rung: **human-in-the-loop
approval**. A risky action can be gated on a single tap — the request,
with its evidence context, reaches you over Telegram; the approval is
bound to that exact action; silence means deny. Design note:
[docs/architecture.md](docs/architecture.md) §8.

## Repository layout

```text
agent-zerotrust/
├── README.md
├── README.ja.md            Japanese README
├── LICENSE                  Apache-2.0
├── docs/
│   ├── architecture.md      components, correlation, fail-safe behavior
│   ├── threat-model.md      assets, adversaries, threats, requirements
│   ├── roadmap.md           phases and exit criteria
│   └── issues/              ready-to-file milestone issues
├── deploy/
│   ├── warpgate/            bastion config, target/user mapping
│   ├── tetragon/            tracing policies (exec / file / network)
│   ├── monitoring/          evidence pipeline, session watcher unit
│   ├── approvals/           MCP gateway systemd unit
│   └── broker/              privileged broker unit + azt-worker CLI
├── guardian/               optional Guardian AI (consumes evidence, never enforces)
│   └── wrappers/            Codex / DSH CLI wrappers
├── evidence/               correlation, case builder, rule backend, Telegram
├── approvals/              MCP gateway: request_approval + worker dispatch
├── broker/                 privileged broker: leases, ledger, policy
├── workers/                Worker Gateway: local CLI agent dispatch
├── policies/
│   ├── network/             Tailscale ACL (applied)
│   └── execution/           execution policy (Phase 3)
└── tests/
    ├── security/            attack-scenario scripts validating the threat model
    └── *.py                 unit tests (65/65)
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
