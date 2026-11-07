"""Session review: warpgate session → correlated evidence → guardian assessment.

Usage (from the repo root):
    python -m evidence.review --latest
    python -m evidence.review --session <session-id> [--json]

Configuration (defaults match the Phase 1 deployment):
    --events-dir            deploy/tetragon/state/events
    --warpgate / $WARGATE_URL          https://<PROTECTED_HOST_IP>:8888
    --admin-password-file   deploy/warpgate/state/admin-password.txt
    $WARGATE_ADMIN_PASSWORD overrides the password file

The backend is the deterministic RuleBackend (AI-optional floor). An LLM
backend can be wired in later without touching this flow — evaluate() is
backend-agnostic (guardian.backends).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from guardian.evaluator import evaluate

from .case_builder import build_case
from .correlate import correlate_session
from .rule_backend import RuleBackend
from .tetragon import load_events
from .warpgate import WarpgateClient

REPO = Path(__file__).resolve().parents[1]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--session", help="warpgate session id")
    ap.add_argument("--latest", action="store_true",
                    help="review the newest completed muse session")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="print the full result as JSON")
    ap.add_argument("--events-dir",
                    default=str(REPO / "deploy/tetragon/state/events"))
    ap.add_argument("--warpgate",
                    default=os.environ.get("WARGATE_URL", "https://<PROTECTED_HOST_IP>:8888"))
    ap.add_argument("--admin-user", default="admin")
    ap.add_argument("--admin-password-file",
                    default=str(REPO / "deploy/warpgate/state/admin-password.txt"))
    args = ap.parse_args(argv)

    password = (os.environ.get("WARGATE_ADMIN_PASSWORD")
                or Path(args.admin_password_file).read_text().strip())
    client = WarpgateClient(args.warpgate, args.admin_user, password).login()
    sessions = client.sessions()

    if args.session:
        session = next((s for s in sessions if s.get("id") == args.session), None)
        if session is None:
            print(f"session {args.session} not found", file=sys.stderr)
            return 2
    else:
        muse = [s for s in sessions
                if s.get("username") == "muse" and s.get("ended")]
        if not muse:
            print("no completed muse sessions", file=sys.stderr)
            return 2
        session = muse[0]  # newest first

    events = load_events(args.events_dir)
    correlated = correlate_session(session, events)
    if correlated is None:
        print("session shell not found in the event stream "
              "(events rotated away?)", file=sys.stderr)
        return 3

    case = build_case(session, correlated)
    result = evaluate(case, RuleBackend())

    if args.as_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    start, end = correlated["window"]
    a = result["assessment"]
    target_name = "?"
    if session.get("target_sessions"):
        target_name = session["target_sessions"][0].get("target", {}).get("name", "?")

    print("=== Session review ===")
    print(f"session   : {session.get('id')}")
    print(f"user      : {session.get('username')} -> {target_name}")
    print(f"window    : {start:%H:%M:%S} – {end:%H:%M:%S} UTC")
    print(f"policy    : {result['policy_tier']} (deterministic floor)")
    print(f"evidence  : {len(result['evidence'])} event(s)")
    print()
    print("Evidence timeline:")
    for ev in result["evidence"]:
        print(f"  [{ev['source']:8s}] {ev['action']}"
              + (f"  ({ev['detail'][:70]})" if ev.get("detail") else ""))
    print()
    print("Assessment (rule backend — AI-optional floor):")
    print(f"  consistency : {a['consistency']}")
    print(f"  summary     : {a['summary']}")
    if a["evidence_ids"]:
        print("  flags       :")
        flagged = {ev["event_id"]: ev["action"] for ev in result["evidence"]}
        for eid in a["evidence_ids"]:
            print(f"    ! {flagged.get(eid, eid)}")
    else:
        print("  flags       : (none)")
    print(f"  next step   : {a['suggested_next_step']}")
    for u in a["uncertainties"]:
        print(f"  uncertainty : {u}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
