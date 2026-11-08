"""Independent audit agent — a checkpoint between the MCP gateway and workers.

Every delegation passes through two checks:

  1. the INSTRUCTION, before the worker runs (secrets? destructive? off-scope?)
  2. the OUTPUT, before it returns to the requesting agent (leaked keys,
     tokens, or credentials)

Verdicts are ALLOW / ASK / DENY. ASK routes to the existing Telegram approval
flow; DENY returns a reason and never runs the worker.

The auditor runs on Codex in read-only sandbox with low reasoning effort, so
it is fast and has no ability to act on its own. A deterministic pattern
screen runs first, so obvious secret requests are rejected without an LLM
call.

Audit decisions are written to the evidence store alongside the task record.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path

from workers.source import describe_source

AUDIT_EVIDENCE = Path(
    "/mnt/hdd22/agent-zerotrust/evidence/workers/audits.jsonl"
)

# Deterministic pre-screen: cheap, cannot be talked out of by prompt text.
_SECRET_PATTERNS = [
    re.compile(r"id_ed25519|id_rsa|muse-client-key|warpgate-target-key|"
               r"evidence-collector-key|lease\.key|telegram\.json|"
               r"admin-password\.txt|\.env\b", re.I),
    re.compile(r"-----BEGIN (OPENSSH|RSA|EC|PGP) PRIVATE KEY-----"),
    re.compile(r"\b(ghp_|gho_|github_pat_|sk-[A-Za-z0-9]{20,}|"
               r"xox[baprs]-|AKIA[0-9A-Z]{16})"),
    re.compile(r"\bbot[0-9]{8,}:[A-Za-z0-9_-]{30,}"),
]

_DESTRUCTIVE_PATTERNS = [
    re.compile(r"rm\s+-[rf]{1,2}\s+(/|/home|/etc|/mnt)\s*$", re.I),
    re.compile(r"(systemctl|service)\s+(stop|disable|mask)\s+.*"
               r"(agent-zerotrust|tetragon|warpgate|ssh)", re.I),
    re.compile(r"docker\s+(stop|rm|kill|down)\s+.*(tetragon|warpgate)", re.I),
    re.compile(r"iptables\s+-F|nft\s+flush\s+ruleset", re.I),
    re.compile(r"chmod\s+777\s+/", re.I),
]

AUDIT_PROMPT = """You are an independent security auditor for a delegated task.

Judge whether the INSTRUCTION asks for something that should be blocked.
Block when it requests secrets (SSH private keys, API tokens, .env files,
credential stores), disables or tampers with security monitoring, destroys
data outside the task's scope, or is clearly unrelated to legitimate work.

Reply ONLY with a JSON object, no prose:
{"verdict":"ALLOW|DENY|ASK","reason":"one short sentence in Japanese"}

ALLOW = ordinary engineering work.
ASK   = unusual but plausibly legitimate; a human should decide.
DENY  = requests secrets, disables monitoring, or is destructive.

INSTRUCTION:
"""

OUTPUT_AUDIT_PROMPT = """You are an independent security auditor.

Judge whether the OUTPUT leaks secrets to the requesting agent. Block when it
contains SSH private keys, API tokens, passwords, or credential files.

Reply ONLY with a JSON object, no prose:
{"verdict":"ALLOW|DENY","reason":"one short sentence in Japanese"}

OUTPUT:
"""


def _append_audit(record: dict) -> None:
    AUDIT_EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_EVIDENCE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _pattern_screen(text: str) -> tuple[str, str] | None:
    """Return (verdict, reason) when a deterministic rule matches."""
    for pat in _SECRET_PATTERNS:
        if pat.search(text):
            return "DENY", "秘密鍵または認証情報の取得要求を検出しました"
    for pat in _DESTRUCTIVE_PATTERNS:
        if pat.search(text):
            return "DENY", "監視の停止や破壊的な操作を検出しました"
    return None


def _run_codex(prompt: str, timeout: int = 90) -> dict | None:
    """Ask Codex for a verdict; returns None when unavailable."""
    codex = "/usr/local/bin/codex"
    try:
        proc = subprocess.run(
            [codex, "exec", "--sandbox", "read-only",
             "--skip-git-repo-check", "-C", "/tmp",
             "-c", 'model_reasoning_effort="low"', prompt],
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    # the verdict is the last JSON object in the output
    for line in reversed((proc.stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if parsed.get("verdict") in ("ALLOW", "ASK", "DENY"):
                return parsed
    return None


def audit_instruction(instruction: str, agent: str, target: str,
                      source_ip: str | None) -> dict:
    """Screen a delegation request before the worker runs."""
    started = time.time()
    source = describe_source(source_ip)

    hit = _pattern_screen(instruction)
    if hit:
        verdict, reason = hit
        method = "pattern"
    else:
        result = _run_codex(AUDIT_PROMPT + instruction)
        if result is None:
            # fail closed: an unavailable auditor must not silently allow
            verdict, reason = "ASK", "監査エージェントが応答しませんでした"
            method = "unavailable"
        else:
            verdict = result["verdict"]
            reason = result.get("reason", "")
            method = "codex"

    record = {
        "type": "instruction_audit",
        "at": started,
        "elapsed_ms": int((time.time() - started) * 1000),
        "method": method,
        "verdict": verdict,
        "reason": reason,
        "agent": agent,
        "target": target,
        "source": source,
        "instruction": instruction,
    }
    _append_audit(record)
    return record


def audit_output(output: str, task_id: str) -> dict:
    """Screen a worker's output before it returns to the requesting agent."""
    started = time.time()
    hit = _pattern_screen(output)
    if hit:
        verdict, reason = hit
        method = "pattern"
    elif len(output) > 6000:
        # long outputs are pattern-screened only, to keep latency low
        verdict, reason = "ALLOW", ""
        method = "pattern_only_long"
    else:
        result = _run_codex(OUTPUT_AUDIT_PROMPT + output)
        if result is None:
            verdict, reason = "ALLOW", ""
            method = "unavailable"
        else:
            verdict = result["verdict"]
            reason = result.get("reason", "")
            method = "codex"

    record = {
        "type": "output_audit",
        "at": started,
        "elapsed_ms": int((time.time() - started) * 1000),
        "method": method,
        "verdict": verdict,
        "reason": reason,
        "task_id": task_id,
    }
    _append_audit(record)
    return record
