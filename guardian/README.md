# Guardian AI — single-backend approval briefing

**Status:** Phase 2 prototype. This component is deliberately **one-shot and advisory**. It is not an autonomous investigation agent or an enforcement mechanism.

## Purpose

An acting agent (e.g. Muse) performs its normal work via **SSH**. When it needs an exception, it supplies an **untrusted explanation (claim)** to the approval control plane via MCP. The trusted security-side service supplies the observed Linux/Warpgate/Tetragon evidence and the **policy-determined** review tier. Guardian compares the two and returns a **brief human-readable assessment**. The human, not Guardian, approves or denies; OS policy/Broker, not Guardian, enforces.

~~~text
SSH -> Warpgate -> Linux -> Tetragon/denial event -----+
                                                       |
MCP approval request -> acting agent's claim ---------+--> Approval Service
                                                       |          |
Deterministic policy -> risk tier ---------------------+          v
                                                        Guardian (one backend)
                                                               |
                                                  structured short assessment
                                                               |
                                                 human approves / clarifies / denies
~~~

## Boundaries and guarantees

- **Only one backend is chosen for each invocation.** No orchestration, consensus, long-running agent sessions, or multi-model comparison.
- **Provider-agnostic interface:** `GuardianBackend.assess(case) -> dict`. `OpenAICompatibleBackend` calls an explicitly configured chat-completions endpoint. `LocalProcessBackend` runs an explicitly configured unprivileged JSON-in/JSON-out wrapper (Codex, OpenCode, Claude Code, Mistral Vibe, Gemini/Antigravity where suitable). CLI adapters are **not bundled**: commands, unattended modes, supported tool permissions and JSON modes differ by runtime and must be integrated/tested separately.
- **Schema-validated model output:** the model cannot issue grants or a final `ALLOW` verdict. Referenced event IDs must exist in the supplied evidence.
- **Short context:** maximum 20 normalized events, a brief claim, and an assigned tier. Evidence and claims are treated as untrusted content inside the model prompt. A generic model output is never an authoritative report of what the kernel did.
- **Fallback:** provider timeout/error/malformed output returns `assessment.status=unavailable` and preserves the redacted evidence and claim for manual review. The approval service does **not** block waiting for the AI and may proceed with a human-only review.
- **No privileged tool execution:** no SSH to the protected host, no direct evidence-store credentials, no Guardian-controlled root privileges. The subprocess backend must run in an OS-level sandbox; its current Python wrapper alone **does not implement sandboxing**.
- **No secret exfiltration by default:** inputs are expected to be redacted **by the trusted calling service before invocation**. The prototype does not implement redaction, provider privacy policy checks, trusted origin verification, structured evidence ingestion, MCP endpoints or an approval queue. Do **not** feed raw sensitive recordings to hosted models.
- **Provenance limitation:** input event IDs and their integrity are the caller's responsibility. The prototype cannot distinguish forged agent-supplied events from trusted event-store records. Do not expose this CLI directly to the acting agent.
- **Policy limitation:** the Guardian returns `review`, `clarify`, or `escalate` suggestions only; these are advisory. A policy-tier downgrade is structurally impossible via the model output.

## Quick start (Python 3.10+, stdlib only)

```bash
python -m unittest discover -s tests -p 'test_guardian*.py'
```

Input example, `request.json` (representative **redacted** data; event IDs are illustrative):

```json
{
  "request_id": "REQ-101",
  "policy_tier": "elevated_ask",
  "evidence": [
    {
      "event_id": "EVT-7",
      "source": "policy_gate",
      "action": "useradd developer",
      "outcome": "denied",
      "observed_at": "2026-11-07T00:00:00Z"
    }
  ],
  "claim": {
    "purpose": "Isolate a Python app",
    "justification": "A separate operating-system account is needed",
    "expected_effect": "One nonprivileged local user"
  }
}
```

Use an **explicit** API endpoint (not restricted to one provider):

```bash
export GUARDIAN_BACKEND=openai_compatible
export GUARDIAN_ENDPOINT='https://YOUR-TRUSTED-ENDPOINT/v1/chat/completions'
export GUARDIAN_MODEL='YOUR-MODEL-ID'
export GUARDIAN_API_KEY='FROM-A-SECRET-MANAGER'
python -m guardian.review < request.json
```

Or a **trusted local wrapper executable** that reads JSON on stdin and prints a JSON assessment on stdout:

```bash
export GUARDIAN_BACKEND=local
export GUARDIAN_COMMAND='/usr/local/bin/guardian-model-wrapper'
python -m guardian.review < request.json
```

Both implementations are replaceable; only one is invoked. The local process receives the structured system instruction and case, and must implement its own model/agent-specific invocation. Restrict the wrapper's OS account, filesystem access, network, and tools. Do not allow the acting agent to set `GUARDIAN_COMMAND` or `GUARDIAN_ENDPOINT`.

Required backend response:

```json
{
  "consistency": "partial",
  "summary": "Creating a system user is relevant to the request, but a Python virtual environment may suffice.",
  "uncertainties": ["The user task itself has not been independently authenticated."],
  "evidence_ids": ["EVT-7"],
  "suggested_next_step": "clarify"
}
```

The caller gets the normalized input and `assessment`, plus `decision_required=true`. The caller must render evidence, agent claim and assessment as **distinct labeled fields**, escape agent-controlled formatting, and avoid including raw secrets or user-supplied links in Telegram notifications.

## Out of scope for this PR

A production deployment still needs a trusted Evidence API, schema versioning, principal/event correlation, lease/grant tracking, redaction rules, the MCP request/response path, approval storage/UI, privilege enforcement, and deployment isolation for agent-process backends. This PR provides the small, independently testable **review function** and backend swap point for those future pieces.

See [architecture](../docs/architecture.md), [roadmap](../docs/roadmap.md) and the separate [execution/approval proposal](../docs/proposals/evidence-intent-approval.md) on its own draft branch.
