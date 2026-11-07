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

import os
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
    client = WarpgateClient(os.environ.get("WARGATE_URL", "https://127.0.0.1:8888"), "admin",
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


SUPPORTED_OP_CLASSES = ("systemctl-restart", "systemctl-start",
                        "systemctl-stop")
LEASE_KEY_PATH = (REPO / "deploy/broker/state/lease.key")
LEASE_TTL = 7200.0  # 2 hours, per the broker/lease design


def request_approval(action: str, justification: str,
                     admin_password: str, events_dir: str,
                     op_class: str = "", op_args: dict | None = None,
                     denial_id: str = "", max_uses: int = 1) -> dict:
    """Create a request; returns the pending view immediately."""
    request_id = f"REQ-{int(time.time())}-{id(action) % 10000:04d}"
    backend, _label = make_backend()
    if op_class:
        if op_class not in SUPPORTED_OP_CLASSES:
            raise ValueError(f"unsupported op_class: {op_class}")
        op_args = op_args or {}
        unit = str(op_args.get("unit", ""))
        if not unit:
            raise ValueError("op_args.unit is required")

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
                                  session_id or "unknown",
                                  op_class=op_class, op_args=op_args,
                                  denial_id=denial_id,
                                  max_uses=max_uses)
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
    if decision == "approved" and view.get("op_class"):
        _mint_lease(request_id, view)
    return store.get_request(request_id), True


def _mint_lease(request_id: str, view: dict) -> None:
    """Mint the signed lease for an approved structured request."""
    from broker import leases as lease_mod
    key = LEASE_KEY_PATH.read_bytes().strip()
    lease_id = f"LSE-{int(time.time())}-{request_id[-4:]}"
    token = lease_mod.mint_lease(
        key,
        lease_id=lease_id,
        request_id=request_id,
        principal="ai-muse",
        op_class=view["op_class"],
        scope={"units": [view.get("op_args", {}).get("unit", "")]},
        ttl_seconds=LEASE_TTL,
        max_uses=store.get_request(request_id)["max_uses"],
    )
    store.add_lease(request_id, lease_id, token)
