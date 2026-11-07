"""Append-only request store for the approval service (four-record model).

Records are JSONL lines in deploy/approvals/state/requests.jsonl:
  {"type": "request",    ...}  the claim + metadata
  {"type": "assessment", ...}  the guardian's advisory output
  {"type": "decision",   ...}  the authoritative human verdict

Nothing is ever overwritten; the latest record of a type wins for reads.
The store lives gateway-side (owned by the service user, mode 0600) —
the acting agent can neither read nor write it.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
STORE_PATH = REPO / "deploy/approvals/state/requests.jsonl"

VALID_DECISIONS = ("approved", "denied")


def _append(record: dict) -> None:
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(STORE_PATH, "a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _records() -> list[dict]:
    if not STORE_PATH.exists():
        return []
    out = []
    for line in open(STORE_PATH, errors="replace"):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def create_request(request_id: str, action: str, justification: str,
                   session_id: str, ttl_seconds: int = 7200,
                   op_class: str = "", op_args: dict | None = None,
                   denial_id: str = "", max_uses: int = 1) -> dict:
    now = time.time()
    record = {
        "type": "request",
        "request_id": request_id,
        "action": action[:1000],
        "justification": justification[:1500],
        "session_id": session_id,
        "created_at": now,
        "expires_at": now + ttl_seconds,
        "claim_version": 1,
        "op_class": op_class or "",
        "op_args": op_args or {},
        "denial_id": denial_id or "",
        "max_uses": max(1, min(int(max_uses or 1), 10)),
    }
    _append(record)
    return record


def add_lease(request_id: str, lease_id: str, token: str) -> None:
    _append({"type": "lease", "request_id": request_id,
            "lease_id": lease_id, "token": token,
            "minted_at": time.time()})


def add_assessment(request_id: str, assessment: dict) -> None:
    _append({"type": "assessment", "request_id": request_id,
             "assessment": assessment})


def add_decision(request_id: str, decision: str, decided_by: str) -> dict:
    if decision not in VALID_DECISIONS:
        raise ValueError(f"invalid decision: {decision}")
    record = {"type": "decision", "request_id": request_id,
              "decision": decision, "decided_by": decided_by,
              "decided_at": time.time()}
    _append(record)
    return record


def get_request(request_id: str) -> dict | None:
    """Latest view of a request: claim, assessment, decision, status."""
    req = None
    assessment = None
    decision = None
    for rec in _records():
        if rec.get("request_id") != request_id:
            continue
        if rec["type"] == "request":
            req = rec
        elif rec["type"] == "assessment":
            assessment = rec["assessment"]
        elif rec["type"] == "decision":
            decision = rec
    if req is None:
        return None
    now = time.time()
    if decision:
        status = decision["decision"]  # approved | denied
    elif now > req["expires_at"]:
        status = "expired"
    else:
        status = "pending"
    lease = None
    for rec in _records():
        if (rec.get("type") == "lease"
                and rec.get("request_id") == request_id):
            lease = rec  # latest wins
    return {
        "request_id": request_id,
        "action": req["action"],
        "justification": req["justification"],
        "created_at": req["created_at"],
        "expires_at": req["expires_at"],
        "op_class": req.get("op_class", ""),
        "op_args": req.get("op_args", {}),
        "max_uses": req.get("max_uses", 1),
        "denial_id": req.get("denial_id", ""),
        "assessment": assessment,
        "decision": decision,
        "lease": ({"lease_id": lease["lease_id"],
                   "token": lease["token"]} if lease else None),
        "status": status,
    }


def pending_request_ids() -> list[str]:
    """Request ids that are still pending (for callback idempotency)."""
    out = []
    for rec in _records():
        if rec.get("type") == "request":
            view = get_request(rec["request_id"])
            if view and view["status"] == "pending":
                out.append(rec["request_id"])
    return out
