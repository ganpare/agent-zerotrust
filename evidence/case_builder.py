"""Build the guardian four-record case payload from correlated events.

The case format is exactly what guardian.evaluator._case() validates:
request_id, policy_tier, evidence[] (≤20 items), claim{}. Evidence items
carry unique event_ids (the evaluator rejects duplicates).

For a post-hoc session review no agent claim exists, so a clearly-marked
placeholder claim is used — the rule backend reports consistency as
insufficient_evidence rather than pretending a comparison happened.
"""
from __future__ import annotations

from .tetragon import event_time, parse_time

MAX_EVENTS = 20

# Paths whose OPEN attempts are evidence-worthy (the do_filp_open hook
# emits every open; the builder keeps only these — kernel-side matchArgs
# does not currently filter on filename args)
SENSITIVE_OPEN_PREFIXES = ("/root/", "/home/", "/etc/ssh/",
                           "/etc/shadow", "/etc/sudoers")


def _fmt(t) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ") if t else ""


def _file_action(kp: dict) -> str | None:
    path, perm = None, None
    for a in kp.get("args") or []:
        if a.get("file_arg"):
            path = a["file_arg"].get("path")
    for a in kp.get("args") or []:
        if a.get("int_arg") is not None:
            perm = a["int_arg"]
    if not path:
        return None
    verb = "read" if perm in (2, 4) else "write" if perm == 2 else "access"
    return f"{verb} {path}"


def _connect_action(kp: dict) -> str:
    for a in kp.get("args") or []:
        sa = a.get("sockaddr_arg")
        if not sa:
            continue
        family = sa.get("family")
        if family in ("AF_INET", "AF_INET6") and sa.get("addr"):
            return f"connect {sa['addr']}:{sa.get('port')}"
        if family == "AF_UNIX":
            return "connect unix-socket"  # local IPC — not network egress
    return "connect (destination not recorded)"


def _open_action(kp: dict) -> tuple[str, str] | None:
    """do_filp_open: (action, outcome). Negative small return = denial."""
    path = None
    for a in kp.get("args") or []:
        if isinstance(a, dict):
            path = a.get("filename_arg") or a.get("string_arg") or path
    if not path or not path.startswith(SENSITIVE_OPEN_PREFIXES):
        return None  # not a sensitive path — drop the noise
    ret = kp.get("return", {}).get("long_arg")
    denied = isinstance(ret, int) and -4095 <= ret <= -1
    return f"open {path}", ("denied" if denied else "allowed")


def _item(event_id: str, source: str, action: str, outcome: str,
          observed_at: str, detail: str = "") -> dict:
    return {
        "event_id": event_id[:128],
        "source": source[:100],
        "action": action[:1000],
        "outcome": outcome[:200],
        "observed_at": observed_at[:80],
        "detail": (detail or "")[:1200],
    }


def build_case(session: dict, correlated: dict, claim: dict | None = None,
               agent_user: str = "ai-muse") -> dict:
    start, end = correlated["window"]
    duration = (end - start).total_seconds()

    target_name = "?"
    if session.get("target_sessions"):
        target_name = session["target_sessions"][0].get("target", {}).get("name", "?")

    items: list[dict] = [_item(
        f"wg-{(session.get('id') or 'unknown')[:8]}",
        "warpgate",
        f"ssh session via warpgate as {agent_user}",
        "recorded",
        _fmt(parse_time(session.get("started"))),
        f"user={session.get('username')} target={target_name} "
        f"duration={duration:.0f}s",
    )]

    # kprobes first (the signal), then execs — capped at MAX_EVENTS
    truncated = 0
    seq = 0
    for e in correlated["kprobes"]:
        seq += 1
        if len(items) >= MAX_EVENTS:
            truncated += 1
            continue
        kp = e["process_kprobe"]
        fn = kp.get("function_name")
        if fn == "security_file_permission":
            action = _file_action(kp)
            outcome = "allowed"
        elif fn == "security_socket_connect":
            action = _connect_action(kp)
            outcome = "allowed"
        elif fn == "do_filp_open":
            parsed = _open_action(kp)
            if parsed is None:
                continue
            action, outcome = parsed
        else:
            action = fn or "kprobe"
            outcome = "allowed"
        if action is None:
            continue
        proc = kp.get("process") or {}
        items.append(_item(
            f"tg{seq:03d}-{(proc.get('exec_id') or '')[-12:]}",
            "tetragon",
            action, outcome, _fmt(event_time(e)),
            f"policy={kp.get('policy_name', '')} binary={proc.get('binary', '')}",
        ))
    for e in correlated["execs"]:
        seq += 1
        if len(items) >= MAX_EVENTS:
            truncated += 1
            continue
        proc = e["process_exec"].get("process") or {}
        items.append(_item(
            f"tg{seq:03d}-{(proc.get('exec_id') or '')[-12:]}",
            "tetragon",
            f"exec {proc.get('binary', '?')}",
            "ok", _fmt(event_time(e)),
            f"args={proc.get('arguments') or ''}",
        ))
    if truncated:
        items[0]["detail"] += f"; {truncated} further events truncated"

    if claim is None:
        claim = {
            "purpose": "Post-hoc session review (no agent claim recorded)",
            "justification": "Evidence-only review of a completed warpgate session",
            "expected_effect": "",
        }

    return {
        "request_id": f"session-review-{(session.get('id') or 'unknown')[:36]}",
        "policy_tier": "ask",  # deterministic floor for session review
        "evidence": items,
        "claim": claim,
    }
