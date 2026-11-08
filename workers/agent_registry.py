"""Agent registry — let the agent define reusable worker agents.

OpenCode discovers agents from `~/.config/opencode/agents/<name>.md`
(Markdown with YAML frontmatter). The agent never writes those files
directly: it asks this module, which validates the name, audits the prompt
with Jev, asks the owner on Telegram when the prompt looks risky, and only
then writes the file.

Safety properties:
  - the name is validated against a strict pattern, so no path traversal
  - an existing agent is never overwritten unless this module created it
  - the prompt is classified before it is written; risky prompts need the
    owner's approval
  - every creation is recorded in the evidence store
  - there is no delete: an agent the agent created stays

Files are written with a `_created_by` marker in the frontmatter so the
gateway can tell its own agents from the owner's.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from workers import jev_audit
from workers.approval_gate import request_worker_approval
from workers.source import describe_source

AGENT_DIR = Path(os.environ.get(
    "AZT_OPENCODE_AGENT_DIR",
    str(Path.home() / ".config/opencode/agents")))

EVIDENCE = Path(
    "/mnt/hdd22/agent-zerotrust/evidence/workers/agents.jsonl")

# lowercase, digits, hyphens; 1-41 chars. No dots, no slashes.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")

MAX_AGENTS = int(os.environ.get("AZT_MAX_WORKER_AGENTS", "20"))

CREATOR = "muse"


def _append(record: dict) -> None:
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    with EVIDENCE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _agent_path(name: str) -> Path:
    """Resolve a name to a path inside AGENT_DIR, or raise."""
    if not NAME_RE.fullmatch(name):
        raise ValueError(
            "name must be 1-41 characters of lowercase letters, digits, "
            "and hyphens (no dots or slashes)")
    full = f"muse-{name}" if not name.startswith("muse-") else name
    path = (AGENT_DIR / f"{full}.md").resolve()
    if not str(path).startswith(str(AGENT_DIR.resolve()) + os.sep):
        raise ValueError("resolved path escapes the agent directory")
    return path


def _owned_by_gateway(path: Path) -> bool:
    if not path.exists():
        return True
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    return f"created-by: {CREATOR}" in text


def _count_agents() -> int:
    if not AGENT_DIR.is_dir():
        return 0
    return sum(1 for p in AGENT_DIR.glob("muse-*.md"))


def create_agent(
    name: str,
    description: str,
    prompt: str,
    model: str = "",
    mode: str = "subagent",
    source_ip: str | None = None,
) -> dict:
    """Create a reusable OpenCode agent, audited and approved by the owner."""
    source_label = describe_source(source_ip)

    try:
        path = _agent_path(name)
    except ValueError as exc:
        return {"status": "rejected", "reason": str(exc)}

    if mode not in ("primary", "subagent", "all"):
        return {"status": "rejected",
                "reason": "mode must be primary, subagent, or all"}

    if not _owned_by_gateway(path):
        return {"status": "rejected",
                "reason": "this agent was created by the owner and cannot be "
                          "changed by the gateway"}

    if not path.exists() and _count_agents() >= MAX_AGENTS:
        return {"status": "rejected",
                "reason": f"the gateway already created {MAX_AGENTS} agents"}

    # Audit the prompt before it is stored.
    audit = jev_audit.classify(prompt)
    if audit["needs_approval"]:
        approval = request_worker_approval(
            instruction=f"エージェント「{name}」の定義:\n\n{prompt}",
            category_label=jev_audit.label(audit["category"]),
            confidence=audit["confidence"],
            agent="opencode",
            target="agent-definition",
            source_label=source_label,
        )
        if not approval["approved"]:
            _append({"type": "agent_rejected", "at": time.time(),
                     "name": name, "reason": approval["reason"],
                     "audit": audit, "source": source_label})
            return {"status": "rejected",
                    "reason": f"承認されませんでした: {approval['reason']}"}

    front = [
        "---",
        f"description: {json.dumps(description, ensure_ascii=False)}",
        f"mode: {mode}",
    ]
    if model:
        front.append(f"model: {model}")
    front += [
        f"created-by: {CREATOR}",
        f"created-at: {time.strftime('%Y-%m-%dT%H:%M:%S%z')}",
        "---",
        "",
        prompt.strip(),
        "",
    ]

    AGENT_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(front), encoding="utf-8")

    record = {
        "type": "agent_created",
        "at": time.time(),
        "name": path.stem,
        "path": str(path),
        "description": description,
        "mode": mode,
        "model": model,
        "prompt": prompt,
        "audit_category": audit["category"],
        "audit_confidence": audit["confidence"],
        "source": source_label,
    }
    _append(record)
    return {"status": "created", "name": path.stem, "path": str(path),
            "audit_category": audit["category"],
            "audit_confidence": audit["confidence"]}


def list_agents() -> list[dict]:
    """List the agents this gateway created."""
    if not AGENT_DIR.is_dir():
        return []
    out = []
    for path in sorted(AGENT_DIR.glob("muse-*.md")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if f"created-by: {CREATOR}" not in text:
            continue
        desc = ""
        m = re.search(r'^description:\s*"?(.*?)"?$', text, re.M)
        if m:
            desc = m.group(1)
        out.append({"name": path.stem, "description": desc,
                    "path": str(path)})
    return out
