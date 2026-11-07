"""One-shot, advisory Guardian assessment of an approval request.

Only trusted services should construct case payloads. Evidence and policy tiers
must come from the enforcement/recording side, not the acting agent.
"""
from __future__ import annotations

import json
from typing import Any, Protocol

MAX_CASE_BYTES = 32_000
MAX_EVENTS = 20
CONSISTENCY = {"aligned", "partial", "mismatch", "insufficient_evidence"}
NEXT_STEPS = {"review", "clarify", "escalate"}
POLICY_TIERS = {"allow", "ask", "elevated_ask", "deny"}


class GuardianBackend(Protocol):
    """Swap the provider without changing the approval workflow."""

    def assess(self, case: dict[str, Any]) -> dict[str, Any]: ...


def _text(value: Any, field: str, *, limit: int = 1500, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    value = value.strip()
    if len(value) > limit or (required and not value):
        raise ValueError(f"{field} has invalid length")
    return value


def _case(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("input must be a JSON object")
    if len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > MAX_CASE_BYTES:
        raise ValueError("case too large; provide a redacted, focused event window")

    request_id = _text(payload.get("request_id"), "request_id", limit=128)
    tier = payload.get("policy_tier")
    if tier not in POLICY_TIERS:
        raise ValueError("policy_tier must be assigned by deterministic policy")

    events = payload.get("evidence")
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ValueError("evidence must be a list of at most 20 events")

    normalized_events: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"evidence[{index}] must be an object")
        eid = _text(event.get("event_id"), "event_id", limit=128)
        if eid in seen:
            raise ValueError("duplicate event_id")
        seen.add(eid)
        normalized_events.append({
            "event_id": eid,
            "source": _text(event.get("source"), "source", limit=100),
            "action": _text(event.get("action"), "action", limit=1000),
            "outcome": _text(event.get("outcome"), "outcome", limit=200),
            "observed_at": _text(event.get("observed_at", ""), "observed_at",
                                 limit=80, required=False),
            "detail": _text(event.get("detail", ""), "detail",
                            limit=1200, required=False),
        })

    claim = payload.get("claim")
    if not isinstance(claim, dict):
        raise ValueError("claim must be an object")
    normalized_claim = {
        "purpose": _text(claim.get("purpose"), "claim.purpose"),
        "justification": _text(claim.get("justification"), "claim.justification"),
        "expected_effect": _text(claim.get("expected_effect", ""),
                                 "claim.expected_effect", required=False),
    }
    # Only whitelisted fields cross the AI boundary. Unknown keys are ignored.
    return {
        "request_id": request_id,
        "policy_tier": tier,
        "evidence": normalized_events,
        "claim": normalized_claim,
    }


def _assessment(raw: Any, event_ids: set[str]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("model response must be an object")
    consistency = raw.get("consistency")
    if consistency not in CONSISTENCY:
        raise ValueError("invalid consistency")
    next_step = raw.get("suggested_next_step")
    if next_step not in NEXT_STEPS:
        raise ValueError("invalid suggested_next_step")

    summary = _text(raw.get("summary"), "summary", limit=900)
    uncertainties = raw.get("uncertainties")
    if not isinstance(uncertainties, list) or len(uncertainties) > 5:
        raise ValueError("invalid uncertainties")
    uncertainties = [
        _text(item, "uncertainty", limit=300) for item in uncertainties
    ]
    references = raw.get("evidence_ids")
    if not isinstance(references, list) or len(references) > MAX_EVENTS:
        raise ValueError("invalid evidence_ids")
    if any(not isinstance(ref, str) or ref not in event_ids for ref in references):
        raise ValueError("unverified evidence citation")

    if not event_ids:
        # A proactive request has no observed denial to corroborate its claim.
        consistency = "insufficient_evidence"
        next_step = "review" if next_step != "escalate" else "escalate"
        if "No observed evidence was supplied." not in uncertainties:
            uncertainties = ["No observed evidence was supplied.",
                             *uncertainties[:4]]

    return {
        "status": "complete",
        "consistency": consistency,
        "summary": summary,
        "uncertainties": uncertainties[:5],
        "evidence_ids": list(dict.fromkeys(references)),
        "suggested_next_step": next_step,
    }


def evaluate(payload: Any, backend: GuardianBackend) -> dict[str, Any]:
    """Provide a human-review briefing; never issue a grant or an ALLOW verdict.

    Provider failures return an unavailable assessment alongside the original
    bounded evidence/claim. The approval UI can still request a human decision.
    """
    case = _case(payload)
    event_ids = {e["event_id"] for e in case["evidence"]}
    try:
        analysis = _assessment(backend.assess(case), event_ids)
    except Exception:
        # Do not leak provider errors, HTTP response bodies, or credentials.
        analysis = {
            "status": "unavailable",
            "consistency": "insufficient_evidence",
            "summary": "Guardian assessment unavailable; review the evidence and claim manually.",
            "uncertainties": ["Automated analysis was not completed."],
            "evidence_ids": [],
            "suggested_next_step": "review",
        }
    return {
        **case,
        "assessment": analysis,
        "decision_required": True,
        "authority": "human_or_separately_authorized_policy",
    }
