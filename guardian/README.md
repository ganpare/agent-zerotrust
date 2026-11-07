# guardian

Optional **Guardian AI**: consumes the correlated evidence timeline
(session → commands → kernel events) and produces risk scores, anomaly
flags, and narrative explanations.

Constraints:

- **Optional by design** — the Phase 1 floor keeps working without it
  (SR5 in [docs/threat-model.md](../docs/threat-model.md))
- Pluggable LLM backend: local GPU or hosted API
- Never on the enforcement path

Lands in Phase 2 — see [docs/roadmap.md](../docs/roadmap.md).
