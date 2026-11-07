# broker — the privileged enforcement point (Phase 3)

The only privileged door for the classes it mediates. The agent user has
no sudo, so nothing privileged happens outside this funnel.

## Flow

```text
agent: azt-broker run systemctl-restart unit=training-web.service
  → DENIED + denial_id (machine-readable, MCP hint)      [deny-only]
agent: MCP request_approval(action, justification, op_class,
                            op_args, denial_id)
  → human taps [承認] on Telegram
  → approval service MINTS a signed lease
agent: get_approval(request_id) → status approved + lease token
agent: azt-broker redeem --lease <token> systemctl-restart \
         unit=training-web.service
  → broker verifies (signature, identity, scope, time, use count)
  → atomically consumes a use slot → executes EXACTLY the bound command
  → every denial and redemption recorded in the ledger
```

## Modules

| Module | Role |
|---|---|
| `leases.py` | Lease tokens: HMAC-signed payload (principal, op_class, scope, window, max_uses); tamper/expiry rejection |
| `ledger.py` | SQLite append-only ledger; atomic use consumption (concurrent double-redeem fails exactly one); denial + use records |
| `policy.py` | v1 operation classes (systemctl restart/start/stop); fixed command templates, strict unit validation, lease-scope matching |
| `server.py` | Root daemon: Unix socket, SO_PEERCRED identity, deny/verify/execute, evidence emission |
| `client.py` | The `azt-broker` CLI (thin; holds no secrets) |

## Security notes

- The lease key (`deploy/broker/state/lease.key`, 0600) is shared between
  the approval service (signs) and the broker (verifies) — both
  gateway-side. Multi-host upgrade path: Ed25519 with pinned pubkeys.
- The executed command is rebuilt from the same validated inputs —
  nothing from the lease or request reaches a shell.
- The broker binds the agent UID (SO_PEERCRED); other users are refused.
- T13: the broker is a high-value target — keep it small; full hardening
  (seccomp, systemd protections) is a follow-up.
- Rollout discipline: landed in deny-only mode first; redemption enabled
  after the ledger and policy were tested.
