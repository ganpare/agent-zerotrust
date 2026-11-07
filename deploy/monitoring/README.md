# deploy/monitoring

The evidence plane: one-way shipping of Warpgate recordings and Tetragon
events to the monitoring host, plus retention and at-rest protection.

Requirements: SR3 (agent cannot reach or modify evidence) and SR4
(evidence may contain secrets — protect it) in
[docs/threat-model.md](../../docs/threat-model.md).

Lands in Phase 1 — see
[docs/issues/001-auditable-ssh-access.md](../../docs/issues/001-auditable-ssh-access.md).
