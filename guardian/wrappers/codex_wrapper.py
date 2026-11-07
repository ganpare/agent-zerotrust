#!/usr/bin/env python3
"""Codex CLI wrapper for the Guardian LocalProcessBackend.

stdin:  {"system_instruction": str, "case": dict}   (as sent by
        guardian.backends.LocalProcessBackend)
stdout: the assessment JSON object

The reviewer agent runs with Codex's READ-ONLY sandbox: it can read files
but cannot write, execute changes, or reach the network — it can only
produce text. Advisory only (SR10): the assessment is never a grant.

Usage (as the LocalProcessBackend argv):
    python3 guardian/wrappers/codex_wrapper.py [CODEX_HOME] [TIMEOUT_S]

CODEX_HOME defaults to ~/.codex. Pass a relocated home when the default
is not writable (e.g. inside a file sandbox): copy auth.json and
config.toml there first. TIMEOUT_S defaults to 240.
"""
from __future__ import annotations

import json
import os
import pwd
import subprocess
import sys


def _home() -> str:
    home = os.environ.get("HOME")
    if home:
        return home
    return pwd.getpwuid(os.getuid()).pw_dir


def extract_agent_text(stdout: str) -> str | None:
    """Return the last agent_message text from codex --json JSONL output."""
    last = None
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = event.get("item") or {}
        if item.get("type") == "agent_message" and item.get("text"):
            last = item["text"]
    return last


def extract_json(text: str) -> dict:
    """Extract the first balanced JSON object from the model's reply."""
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in the model reply")
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("unbalanced JSON in the model reply")


def main() -> int:
    payload = json.load(sys.stdin)
    system_instruction = payload.get("system_instruction", "")
    case = payload.get("case", {})

    codex_home = sys.argv[1] if len(sys.argv) > 1 else os.path.join(_home(), ".codex")
    timeout_s = int(sys.argv[2]) if len(sys.argv) > 2 else 240

    prompt = (
        system_instruction
        + "\n\nAnalyze the following approval case and return ONLY the JSON "
          "object as specified above.\n\nCase:\n"
        + json.dumps(case, ensure_ascii=False)
    )

    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": _home(),
        "LANG": "C.UTF-8",
        "CODEX_HOME": codex_home,
    }
    argv = [
        "codex", "exec",
        "--json",
        "--sandbox", "read-only",
        "--skip-git-repo-check",
        "-C", "/tmp",
        prompt,
    ]
    proc = subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout_s, env=env)
    text = extract_agent_text(proc.stdout)
    if proc.returncode != 0 or text is None:
        print(f"codex wrapper: agent failed "
              f"(rc={proc.returncode}, message={'yes' if text else 'none'})",
              file=sys.stderr)
        return 1
    assessment = extract_json(text)
    print(json.dumps(assessment, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
