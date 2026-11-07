#!/usr/bin/env python3
"""DSH (DeepSeek Harness) wrapper for the Guardian LocalProcessBackend.

stdin:  {"system_instruction": str, "case": dict}   (as sent by
        guardian.backends.LocalProcessBackend)
stdout: the assessment JSON object

Uses `dsh headless` — one task, one answer, exit. The reviewer agent runs
with the invoking user's tool policy; on a file-sandboxed host that means
workspace-only writes. On an unsandboxed deployment, run the guardian
under its own confinement (the reviewer must only produce text — SR10).

Usage (as the LocalProcessBackend argv):
    python3 guardian/wrappers/dsh_wrapper.py [DSH_HOME] [TIMEOUT_S]

DSH_HOME defaults to ~/.dsh. Pass a relocated home when the default is
not writable (e.g. inside a file sandbox): copy the ~/.dsh tree there
first (it contains the harness credentials — keep it out of git).
TIMEOUT_S defaults to 240.
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


def _find_dsh() -> str:
    """Locate the dsh binary even under a minimal PATH (the
    LocalProcessBackend passes only os.defpath, and dsh typically lives
    in an nvm bin directory)."""
    import glob
    import shutil
    found = shutil.which("dsh")
    if found:
        return found
    candidates = (
        glob.glob(os.path.join(_home(), ".nvm/versions/node/*/bin/dsh"))
        + ["/usr/local/bin/dsh", "/usr/bin/dsh"]
    )
    for path in candidates:
        if os.access(path, os.X_OK):
            return path
    raise FileNotFoundError("dsh binary not found (tried PATH, nvm, /usr/local/bin)")


def extract_json(text: str) -> dict:
    """Extract the first balanced JSON object from the reply."""
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in the reply")
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
    raise ValueError("unbalanced JSON in the reply")


def main() -> int:
    payload = json.load(sys.stdin)
    system_instruction = payload.get("system_instruction", "")
    case = payload.get("case", {})

    dsh_home = sys.argv[1] if len(sys.argv) > 1 else os.path.join(_home(), ".dsh")
    timeout_s = int(sys.argv[2]) if len(sys.argv) > 2 else 240

    prompt = (
        system_instruction
        + "\n\nAnalyze the following approval case and return ONLY the JSON "
          "object as specified above. Do not use any tools; answer directly.\n\n"
          "Case:\n"
        + json.dumps(case, ensure_ascii=False)
    )

    dsh = _find_dsh()
    env = dict(os.environ)
    env["DSH_HOME"] = dsh_home
    env["HOME"] = _home()
    env["PATH"] = os.path.dirname(dsh) + os.pathsep + env.get("PATH", "")
    argv = [dsh, "headless", prompt]
    proc = subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout_s, env=env)
    if proc.returncode != 0 or not proc.stdout.strip():
        print(f"dsh wrapper: headless run failed (rc={proc.returncode})",
              file=sys.stderr)
        return 1
    assessment = extract_json(proc.stdout)
    print(json.dumps(assessment, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
