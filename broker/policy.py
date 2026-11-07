"""Operation classes v1: systemctl restart/start/stop for specific units.

Commands are built from fixed templates — no shell, no metacharacters.
The unit name is validated strictly and must appear in the lease scope
(exact match). This is the TOCTOU-resistant binding point: the lease
names the units, the request is checked against it, and the executed
command is rebuilt from the same validated inputs.
"""
from __future__ import annotations

import re

UNIT_RE = re.compile(r"[A-Za-z0-9_.@:-]+[.]service")

OPERATIONS: dict[str, list[str]] = {
    "systemctl-restart": ["systemctl", "restart", "{unit}"],
    "systemctl-start":   ["systemctl", "start", "{unit}"],
    "systemctl-stop":    ["systemctl", "stop", "{unit}"],
}


class PolicyError(ValueError):
    pass


def build_command(op_class: str, args: dict) -> list[str]:
    if op_class not in OPERATIONS:
        raise PolicyError(f"unknown op_class: {op_class}")
    unit = str(args.get("unit", ""))
    if not UNIT_RE.fullmatch(unit):
        raise PolicyError(f"invalid unit name: {unit!r}")
    return [part.format(unit=unit) for part in OPERATIONS[op_class]]


def lease_covers(payload: dict, op_class: str, args: dict) -> bool:
    if payload.get("op_class") != op_class:
        return False
    units = (payload.get("scope") or {}).get("units") or []
    return args.get("unit") in units
