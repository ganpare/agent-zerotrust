# policies/execution

Execution policy (Phase 3): default-deny execution for the agent user,
implemented as Tetragon tracing / enforcement policies.

Rollout discipline: **detect-only first, then enforce** — never straight
to blocking. See [docs/roadmap.md](../../docs/roadmap.md) Phase 3.
