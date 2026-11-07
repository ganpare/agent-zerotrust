"""Correlate a Warpgate session with Tetragon events.

Join key (architecture §3): the session's shell — the bash whose parent is
sshd, spawned at the start of the session's window — plus process-tree
ancestry over exec_ids, scoped to the fixed agent OS user. Timestamps alone
are a fallback, not proof; the ancestry walk is the correlation.

Known limitation (PoC): two overlapping sessions are disambiguated only by
picking the shell closest to each session's start time.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from .tetragon import event_time, event_type, parse_time

SHELL_BINARIES = {"/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh"}
SSHD_BINARY = "/usr/sbin/sshd"


def session_window(session: dict) -> tuple[datetime, datetime]:
    """Prefer the target session's times — closest to the shell spawn."""
    targets = session.get("target_sessions") or []
    start = parse_time(session.get("started"))
    end = parse_time(session.get("ended"))
    if targets:
        start = parse_time(targets[0].get("started")) or start
        end = parse_time(targets[-1].get("ended")) or end
    if start is None or end is None:
        raise ValueError("session has no usable timestamps")
    return start, end


def _chain_reaches(exec_id, target_id: str, parent_of: dict, max_hops: int = 15) -> bool:
    current = exec_id
    for _ in range(max_hops):
        if current == target_id:
            return True
        current = parent_of.get(current) if current else None
        if current is None:
            return False
    return False


def correlate_session(session: dict, events: list[dict], agent_uid: int = 1001,
                      margin: timedelta = timedelta(seconds=3)) -> dict | None:
    """Return the events belonging to one warpgate session, or None if the
    session shell cannot be found (e.g., events already rotated away)."""
    start, end = session_window(session)
    window_start, window_end = start - margin, end + margin

    # exec_id -> parent_exec_id index; parents may have started before the
    # window, so index generously around it
    parent_of: dict[str, str] = {}
    for e in events:
        proc = (e.get("process_exec") or e.get("process_exit")
                or e.get("process_kprobe") or {}).get("process") or {}
        eid, peid = proc.get("exec_id"), proc.get("parent_exec_id")
        if not eid or not peid:
            continue
        t = event_time(e)
        if t is None or (start - timedelta(minutes=5)) <= t <= window_end:
            parent_of[eid] = peid

    # seed: the session shell (bash under sshd, at session start)
    seed, best = None, None
    for e in events:
        if event_type(e) != "exec":
            continue
        p = e["process_exec"]
        proc, par = p.get("process") or {}, p.get("parent") or {}
        if proc.get("uid") != agent_uid or proc.get("binary") not in SHELL_BINARIES:
            continue
        if par.get("binary") != SSHD_BINARY:
            continue
        t = event_time(e)
        if t is None or not (window_start <= t <= start + timedelta(seconds=10)):
            continue
        delta = abs((t - start).total_seconds())
        if best is None or delta < best:
            seed, best = e, delta
    if seed is None:
        return None

    seed_id = seed["process_exec"]["process"]["exec_id"]
    out = {"seed": seed, "execs": [], "exits": [], "kprobes": [],
           "window": (start, end)}
    for e in events:
        payload = e.get("process_exec") or e.get("process_exit") or e.get("process_kprobe")
        if not payload:
            continue
        proc = payload.get("process") or {}
        eid = proc.get("exec_id")
        if not eid:
            continue
        t = event_time(e)
        if t is None or not (window_start <= t <= window_end):
            continue
        if eid == seed_id or (
            proc.get("uid") == agent_uid
            and _chain_reaches(proc.get("parent_exec_id"), seed_id, parent_of)
        ):
            kind = event_type(e)
            if kind == "exec":
                out["execs"].append(e)
            elif kind == "exit":
                out["exits"].append(e)
            elif kind == "kprobe":
                out["kprobes"].append(e)
    out["execs"].sort(key=lambda e: event_time(e) or start)
    out["kprobes"].sort(key=lambda e: event_time(e) or start)
    return out
