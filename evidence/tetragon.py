"""Tetragon JSONL event loading and helpers (stdlib only)."""
from __future__ import annotations

import json
import os
from datetime import datetime


def load_events(events_dir: str) -> list[dict]:
    """Load all events — the current export plus rotated files — from a dir."""
    events: list[dict] = []
    for name in sorted(os.listdir(events_dir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(events_dir, name), "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


def parse_time(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def event_time(event: dict) -> datetime | None:
    return parse_time(event.get("time"))


def event_type(event: dict) -> str:
    if "process_exec" in event:
        return "exec"
    if "process_exit" in event:
        return "exit"
    if "process_kprobe" in event:
        return "kprobe"
    return "other"


def payload(event: dict) -> dict:
    return (event.get("process_exec") or event.get("process_exit")
            or event.get("process_kprobe") or {})


def process(event: dict) -> dict:
    return payload(event).get("process") or {}
