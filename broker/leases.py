"""Permission leases: signed, bounded, action-bound authorization objects.

A lease is what the approval service MINTS when a human approves, and what
the privileged broker VERIFIES and REDEEMS. Token format:

    base64url(payload_json) + "." + base64url(hmac_sha256(key, payload))

The key is shared between the approval service (signs) and the broker
(verifies) — both gateway-side, both outside the agent's reach. (The
multi-host design upgrades this to Ed25519 with pinned public keys; see
docs/proposals/privileged-broker-and-lease.md.)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


class LeaseError(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def mint_lease(key: bytes, *, lease_id: str, request_id: str,
               principal: str, op_class: str, scope: dict,
               ttl_seconds: float = 7200.0, max_uses: int = 1) -> str:
    now = time.time()
    payload = {
        "lease_id": lease_id,
        "request_id": request_id,
        "principal": principal,
        "op_class": op_class,
        "scope": scope,
        "not_before": now,
        "not_after": now + ttl_seconds,
        "max_uses": max_uses,
    }
    body = _b64(json.dumps(payload, sort_keys=True).encode())
    sig = _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_lease(key: bytes, token: str) -> dict:
    if not isinstance(token, str) or token.count(".") != 1:
        raise LeaseError("malformed token")
    body, _, sig = token.partition(".")
    expected = _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        raise LeaseError("bad signature")
    try:
        payload = json.loads(_unb64(body))
    except (ValueError, json.JSONDecodeError) as exc:
        raise LeaseError("malformed payload") from exc
    now = time.time()
    if now < payload.get("not_before", 0):
        raise LeaseError("not yet valid")
    if now > payload.get("not_after", 0):
        raise LeaseError("expired")
    for field in ("lease_id", "principal", "op_class", "scope", "max_uses"):
        if field not in payload:
            raise LeaseError(f"missing field: {field}")
    return payload
