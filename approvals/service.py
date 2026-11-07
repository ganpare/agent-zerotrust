"""The approval service: request → evidence → assessment → briefing → decision.

Implements the Phase 2 advisory flow (architecture §8):
- request_approval returns IMMEDIATELY with a pending status (async — the
  human answers whenever they see the Telegram briefing)
- the claim is stored as the untrusted Claim record; the guardian
  compares it against the current session's Evidence
- the human's button tap records the Decision; get_approval returns it
- nothing here grants OS permissions (Phase 3 adds enforcement)
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from guardian.evaluator import evaluate

from . import store
from evidence.case_builder import build_case
from evidence.correlate import correlate_session
from evidence.review import make_backend
from evidence.telegram import (TelegramConfigError, format_request_briefing,
                                load_config, request_keyboard, send_message)
from evidence.warpgate import WarpgateClient

REPO = __import__("pathlib").Path(__file__).resolve().parents[1]


def _warpgate(admin_password: str) -> WarpgateClient:
    client = WarpgateClient("https://<PROTECTED_HOST_IP>:8888", "admin",
                            admin_password)
    return client.login()


def current_session_case(client: WarpgateClient, events_dir: str,
                         claim: dict) -> tuple[dict, dict | None]:
    """Build a guardian case from the agent's CURRENT session context."""
    from evidence.tetragon import load_events
    sessions = [s for s in client.sessions() if s.get("username") == "muse"]
    session = sessions[0] if sessions else None
    if session is None:
        # no session yet — an empty-evidence case; the guardian reports
        # insufficient_evidence for uncorroborated proactive claims
        return {"request_id": "no-session", "policy_tier": "ask",
                "evidence": [], "claim": claim}, None
    if session.get("ended") is None:
        session = {**session,
                   "ended": datetime.now(timezone.utc).isoformat()}
    events = load_events(events_dir)
    correlated = correlate_session(session, events)
    if correlated is None:
        return {"request_id": session.get("id", "?"), "policy_tier": "ask",
                "evidence": [], "claim": claim}, session
    return build_case(session, correlated, claim=claim), session


def request_approval(action: str, justification: str,
                     admin_password: str, events_dir: str) -> dict:
    """Create a request; returns the pending view immediately."""
    request_id = f"REQ-{int(time.time())}-{id(action) % 10000:04d}"
    backend, _label = make_backend()

    claim = {"purpose": action, "justification": justification,
             "expected_effect": ""}
    try:
        client = _warpgate(admin_password)
        case, session = current_session_case(client, events_dir, claim)
        session_id = (session or {}).get("id")
    except Exception:
        case = {"request_id": request_id, "policy_tier": "ask",
                "evidence": [], "claim": claim}
        session_id = None

    request = store.create_request(request_id, action, justification,
                                  session_id or "unknown")
    result = evaluate(case, backend)
    store.add_assessment(request_id, result["assessment"])

    try:
        config = load_config()
        text = format_request_briefing(result, request)
        send_message(config, text, reply_markup=request_keyboard(request_id))
    except TelegramConfigError:
        pass  # the request is still recorded; the human can review it

    return store.get_request(request_id)


def decide(request_id: str, decision: str) -> tuple[dict, bool]:
    """Record a human decision. Returns (view, changed)."""
    if decision not in store.VALID_DECISIONS:
        raise ValueError(f"invalid decision: {decision}")
    view = store.get_request(request_id)
    if view is None:
        return {"request_id": request_id, "status": "unknown"}, False
    if view["status"] != "pending":
        return view, False  # already decided / expired — idempotent
    store.add_decision(request_id, decision,
                       decided_by="telegram:human")
    return store.get_request(request_id), True
