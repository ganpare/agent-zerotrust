# Privileged broker vs. existing mechanisms — comparison and lease design

**Status:** design stage, pre-implementation. Per the project direction:
compare before committing to an approach; **Phase 1 (Warpgate + Tetragon)
remains the priority**; no broker/lease implementation yet.
**Related:** [architecture](../architecture.md) §8.7–8.8;
[threat model](../threat-model.md) T13, SR8, SR10; [evidence–intent proposal](evidence-intent-approval.md).

## 1. The requirement

The Phase 3 "ask" verdict needs a redemption point on the protected host
that can:

1. mint **machine-readable denial IDs** carrying the exact action spec;
2. verify a **grant or lease** and redeem it **atomically** (single-use
   for grants; per-use-verified for leases);
3. execute **exactly the bound action** with privilege — nothing broader;
4. **revalidate bindings at redemption** (TOCTOU defense);
5. emit **structured evidence** for every denial, redemption, and
   execution;
6. do all of this **without broadening the agent user's privileges**.

Generic OS refusals satisfy none of these: a plain `EPERM` or a stock
sudo refusal carries no denial ID and cannot redeem anything.

## 2. Options compared

| Criterion | sudo + generated sudoers | polkit | Scoped privileged broker |
|---|---|---|---|
| Dynamic per-grant authorization | Poor — static config; per-grant snippets mean generating/removing sudoers.d files with racy lifecycle and no one-shot semantics | Limited — actions are statically declared; per-request dynamic grants do not fit the action model; rules cannot query a grant store | Native — grants/leases are first-class and checked at redemption |
| Denial-ID minting | No (generic refusal) | Partial (dialogs, not machine-readable for our flow) | Yes, with the exact action spec |
| TOCTOU revalidation at redemption | No | No | Yes (digest/argv/cwd recheck; `openat2`-style path discipline) |
| Lease semantics (repeat use, per-use verification) | No — timestamp caching is time-based, not scope-based | No | Yes |
| Atomic single-use redemption | No | No | Yes (local append-only ledger, unique-ID constraint) |
| Structured evidence emission | Text logs | Journal text | Structured events + ledger, shipped off-host |
| New attack surface | The config-generation glue; sudoers files are an on-host tamper target | polkitd + JS rules; heavyweight for headless servers | A new small privileged daemon (T13) — mitigations in §4 |
| Maturity of the privileged core | Very high | High | Ours to build and harden |

**Verdict (current, to be revisited):** the broker — possibly *using*
sudo or systemd primitives as internal substrates where convenient —
because mediation, binding, redemption, and ledger logic are the actual
requirements, and none of the existing tools provide them. The broker
keeps the privileged surface smaller than sudo-with-generated-rules and
simpler than polkit on a headless host.

## 3. Permission lease — data model (design)

```json
{
  "lease_id": "LSE-2041",
  "request_id": "REQ-2038",
  "agent_principal": "verified:muse",
  "operation_class": "systemctl-restart",
  "scope": { "units": ["training-web.service"] },
  "not_before": "2026-11-07T18:00:00Z",
  "not_after": "2026-11-07T20:00:00Z",
  "max_uses": 10,
  "binding": { "argv_template": ["systemctl", "restart", "{unit}"],
               "constraints": { "unit": ["training-web.service"] } },
  "signature": "ed25519:..."
}
```

Lifecycle: `requested → decided → active → expired | exhausted | revoked`.

Per-use verification by the broker, in order:

1. caller identity via `SO_PEERCRED` (kernel-guaranteed uid → principal);
2. signature and revocation-list check (offline-verifiable);
3. operation-class and scope match — the requested operation must be an
   instance of the leased class within scope;
4. expiry and use-count check;
5. binding recheck (TOCTOU rules, architecture §8.2);
6. **atomic ledger append** (use event, unique lease-use ID) — a
   concurrent double-use fails exactly one;
7. execute; append the result event.

Evidence chain (append-only, off-host): **Request ID → Decision →
Lease ID → use events → results**. This is what makes an approved
permission traceable to *when and for which concrete operations it was
used* — the same chain serves approval auditing and, later, incident
investigation and privileged-ID management analysis.

## 4. Broker hardening requirements (threat T13)

- Minimal code; no parsing of agent input beyond the binding spec.
- seccomp-restricted; systemd hardening; split capabilities where
  possible (execution broker vs. egress-allowlist updater).
- Dedicated Unix socket, `SO_PEERCRED` uid check; no network listener.
- Signed grants/leases (Ed25519, pinned public keys, documented
  rotation procedure); signed revocation lists for kill-switch
  propagation.
- Local append-only redemption ledger, shipped off-host with all other
  evidence.
- Tetragon static denies as the funnel backstop (privileged execution
  outside the broker is killed).

## 5. Open questions

- Operation-class taxonomy for v1 (`systemctl-restart`,
  `package-install`, `egress-destination`, `create-user`, ...).
- Leases for egress: proxy allowlist entries with TTL (likely) vs.
  per-lease nftables updates.
- Revocation propagation latency to brokers (signed revocation lists
  pulled at an interval vs. pushed).
- Whether `systemd-run` transient units can serve as the execution
  substrate for restart-class leases.
- CLI redemption path for non-MCP agents — same broker, different
  front end?

## 6. Non-goals (this stage)

- No implementation of the broker or lease logic.
- No change to Phase 1 scope or the Milestone 1 acceptance criteria.
