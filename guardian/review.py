"""Run one Guardian review from a bounded JSON case on stdin.

Examples:
    GUARDIAN_BACKEND=local GUARDIAN_COMMAND=/path/to/trusted-wrapper \
        python -m guardian.review < request.json

    GUARDIAN_BACKEND=openai_compatible GUARDIAN_ENDPOINT=https://.../v1/chat/completions \
        GUARDIAN_MODEL=... GUARDIAN_API_KEY=... \
        python -m guardian.review < request.json

The caller is a trusted Approval Service, not the acting agent. The caller
must supply verified policy tiers and server-side evidence.
"""
from __future__ import annotations

import json
import os
import shlex
import sys

from guardian.backends import LocalProcessBackend, OpenAICompatibleBackend
from guardian.evaluator import evaluate


def main() -> int:
    try:
        provider = os.environ.get("GUARDIAN_BACKEND", "").strip()
        if provider == "openai_compatible":
            endpoint = os.environ["GUARDIAN_ENDPOINT"]
            model = os.environ["GUARDIAN_MODEL"]
            key = os.environ["GUARDIAN_API_KEY"]
            backend = OpenAICompatibleBackend(endpoint, model, key)
        elif provider == "local":
            # Config is trusted deployment environment, never an agent claim.
            argv = shlex.split(os.environ["GUARDIAN_COMMAND"])
            backend = LocalProcessBackend(tuple(argv))
        else:
            raise ValueError("Set GUARDIAN_BACKEND=local or openai_compatible")

        payload = json.load(sys.stdin)
        output = evaluate(payload, backend)
        print(json.dumps(output, ensure_ascii=False))
        return 0
    except (ValueError, KeyError, json.JSONDecodeError):
        # Avoid printing evidence content and configuration secrets.
        print("guardian: invalid configuration or case", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
