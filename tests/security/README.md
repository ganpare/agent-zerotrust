# tests/security

Attack-scenario scripts that validate the threat model end-to-end. Each
scenario maps to a threat ID in
[docs/threat-model.md](../../docs/threat-model.md):

- **T5** — a direct-SSH bypass attempt must fail
- **T2** — reading a planted secret file must show up in the evidence
- **T6** — an evidence-tampering attempt by the agent user must fail
- **T4** — an outbound connection to an unexpected destination must be
  captured

Runs against the Phase 1 deployment; used as the acceptance harness for
[docs/issues/001-auditable-ssh-access.md](../../docs/issues/001-auditable-ssh-access.md).

Phase 3 adds the twelve attack-oriented validation scenarios from the
evidence–intent proposal (draft PR #1) — claim/evidence agreement, false
claims, unverified denials, prompt injection, identity spoofing, TOCTOU,
replay/race, outage, approval fatigue, privileged-retry, and operator
training — each mapped to a threat ID above.
