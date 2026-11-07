# evidence — the seed of the Evidence API

Correlates Warpgate sessions with Tetragon events into the guardian
four-record case format, and runs a session review end-to-end:

```text
warpgate admin API ──┐
                      ├─→ correlate → case builder → guardian.evaluate() → briefing
tetragon JSONL ───────┘                                (RuleBackend = AI-optional floor)
```

This is the Phase 2 bridge the roadmap calls for: the correlated evidence
timeline (session → commands → kernel events) as a service, wired to the
merged `guardian/` review function.

## Usage (from the repo root, on the protected host)

```bash
python -m evidence.review --latest          # newest completed muse session
python -m evidence.review --session <id>    # a specific session
python -m evidence.review --latest --json    # full machine-readable result
```

Configuration: `--events-dir`, `--warpgate` / `$WARGATE_URL`,
`--admin-password-file` / `$WARGATE_ADMIN_PASSWORD`. Defaults match the
Phase 1 deployment.

## Modules

| Module | Role |
|---|---|
| `tetragon.py` | JSONL loading (current + rotated exports), event helpers |
| `warpgate.py` | Minimal admin API client (stdlib, session cookie) |
| `correlate.py` | Session ↔ events join: window + shell seed (bash under sshd) + exec_id ancestry, scoped to the agent UID |
| `case_builder.py` | Guardian case payload: warpgate record + kprobes + execs (≤20), placeholder claim for post-hoc review |
| `rule_backend.py` | Deterministic `GuardianBackend`: sensitive reads, persistence writes, external connects → flags; advisory only (SR10 — raises, never grants) |
| `review.py` | CLI: session → case → assessment → human briefing |

## Design notes

- **AI-optional floor**: the default backend is `RuleBackend` — pure rules,
  no LLM. An LLM backend (`guardian.backends`) drops into the same
  `evaluate()` call without touching this flow.
- **Post-hoc reviews carry a placeholder claim** (clearly marked), so the
  assessment honestly reports `insufficient_evidence` for consistency —
  the four-record model does not pretend a comparison happened.
- **The connect policy now extracts destinations** (`sockaddr` arg):
  evidence shows *where*, not just *that* a connection happened.
  AF_UNIX connects are labeled `connect unix-socket` (local IPC, not
  egress). Events recorded before the policy update lack destinations.
- **Placement**: the PoC runs on the protected host (live API + local
  spool). Production placement is the monitoring host reading pulled
  evidence — this package only needs `load_events(dir)` + session data,
  so it moves without code changes.

## Known limitations (PoC)

- Overlapping sessions are disambiguated by nearest-shell-start only.
- `process_exit` events carry no exit code in this Tetragon version, so
  exec outcomes are "ok" rather than exit-status-annotated.
- The case caps evidence at 20 items (guardian schema); kprobes are
  prioritized over execs, truncation is noted in the session record.
