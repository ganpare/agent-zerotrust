# Muse onboarding card

Everything Muse's owner needs to hand over. Copy the relevant sections
into Muse's configuration and instructions.

## 1. Muse network settings

| Setting | Value | Why |
|---|---|---|
| アウトバウンドSSH | **ON** | the SSH work path (port 22 → Warpgate) |
| その他のTCP接続 | **ON** | the MCP approvals server (`<PROTECTED_HOST_IP>:8930`) |
| その他すべて | OFF | not needed for this host |

Port 22 on the Tailscale IP **is Warpgate** (redirected to its 2222
listener) — a standard SSH client on the standard port works. Direct
sshd does not exist on the tailnet.

## 2. SSH connection

Transfer the agent key to Muse's host (from the protected host:
`deploy/warpgate/state/muse-client-key`; keep it mode 0600):

    ssh -i <path>/muse-client-key -p 22 muse:<PROTECTED_HOST>-local@<PROTECTED_HOST_IP>

- Username format is `muse:<PROTECTED_HOST>-local` (warpgate user:target)
- Lands as the unprivileged OS user `ai-muse`
- No sudo exists; everything is recorded and audited

## 3. MCP server

    url: http://<PROTECTED_HOST_IP>:8930/mcp
    tools:
      request_approval(action, justification, ...)  -> returns pending immediately
      get_approval(request_id)                      -> pending | approved | denied | expired
      list_worker_agents()                          -> available CLI agents (codex, dsh, opencode, commandcode, vibe, agy)
      dispatch_worker_task(agent, instruction, target="linux"|"windows", workdir=..., wait_seconds=25)
                                                    -> delegates work to a local agent (use target="windows" to operate on the Windows host via SSH with full RTX 4090 access)
      get_worker_task(task_id)                      -> status + output preview of a running/completed worker task

## 4. Instructions for Muse (paste into its system prompt / AGENTS.md)

> You work on a protected Linux host as the unprivileged user `ai-muse`.
> Every command you run, every file you open, and every connection you
> make is recorded at the kernel level and audited. Work normally within
> your permissions.
>
> When an operation is denied (Permission denied) or you need an
> exception, do NOT retry blindly and do NOT look for workarounds.
> Instead call the MCP tool `request_approval` with:
> - `action`: the EXACT command or operation you intend to run
> - `justification`: honestly, why it is needed for the user's task
>
> `request_approval` returns immediately with status `pending`. Do not
> wait; continue with other work. Later, call `get_approval` with the
> request_id. Silence is not approval: if the request expires, treat it
> as denied and propose an alternative to the user instead.
>
> Never attempt to disable or evade the monitoring, never modify
> warpgate/tetragon configuration, and never share the SSH key.
> Your approval request text ("claim") is shown to the human together
> with the kernel evidence of what you actually did — describe your
> intent accurately.

## 5. What the owner sees (no action needed)

- Every session is recorded and replayable in the warpgate admin UI
- Each completed session is auto-reviewed and briefed to Telegram
- Approval requests arrive on Telegram with [✅ 承認] [🚫 拒否] buttons;
  the decision is returned to the agent via `get_approval`
