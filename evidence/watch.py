"""Watch for completed agent sessions; review and notify automatically.

The watcher closes the Phase 2 loop: a session ends → it is correlated,
assessed, and a briefing lands on Telegram — without anyone running
anything by hand.

Usage:
    python -m evidence.watch               # loop (default: 60s interval)
    python -m evidence.watch --once        # single pass (for timers)

State: deploy/monitoring/state/watch-state.json — the set of reviewed
session ids. On the FIRST run, all currently-completed muse sessions are
marked as reviewed WITHOUT notifying (baseline); only sessions that
complete afterwards trigger briefings.

The backend follows GUARDIAN_BACKEND (default: rule — deterministic and
fast; point it at an LLM wrapper for semantic assessments). Telegram
configuration comes from the same place as evidence.telegram (env or
deploy/monitoring/state/telegram.json); if Telegram is not configured,
reviews are still recorded and the watcher logs instead of failing.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from guardian.evaluator import evaluate

from .case_builder import build_case
from .correlate import correlate_session
from .review import make_backend
from .tetragon import load_events
from .warpgate import WarpgateClient

REPO = Path(__file__).resolve().parents[1]
STATE_PATH = REPO / "deploy/monitoring/state/watch-state.json"


def load_state() -> set:
    if STATE_PATH.exists():
        return set(json.loads(STATE_PATH.read_text()).get("reviewed", []))
    return set()


def save_state(reviewed: set) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps({"reviewed": sorted(reviewed)}))


def completed_muse_sessions(client: WarpgateClient) -> list:
    return [s for s in client.sessions()
            if s.get("username") == "muse" and s.get("ended")]


def review_one(session: dict, events_dir: str, backend):
    events = load_events(events_dir)
    correlated = correlate_session(session, events)
    if correlated is None:
        return None  # events rotated away — nothing to review
    case = build_case(session, correlated)
    return evaluate(case, backend)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--once", action="store_true",
                    help="run a single pass and exit")
    ap.add_argument("--interval", type=int, default=60,
                    help="poll interval in seconds (loop mode)")
    ap.add_argument("--events-dir",
                    default=str(REPO / "deploy/tetragon/state/events"))
    ap.add_argument("--warpgate",
                    default="https://<PROTECTED_HOST_IP>:8888")
    ap.add_argument("--admin-user", default="admin")
    ap.add_argument("--admin-password-file",
                    default=str(REPO / "deploy/warpgate/state/admin-password.txt"))
    args = ap.parse_args(argv)

    password = Path(args.admin_password_file).read_text().strip()
    backend, backend_label = make_backend()

    try:
        from .telegram import (TelegramConfigError, format_briefing,
                               load_config, send_message)
        telegram = load_config()
    except TelegramConfigError as exc:
        print(f"watcher: telegram not configured — {exc}", file=sys.stderr)
        telegram = None

    reviewed = load_state()
    first_pass = not STATE_PATH.exists()

    while True:
        client = WarpgateClient(args.warpgate, args.admin_user,
                                password).login()
        sessions = completed_muse_sessions(client)
        new = [s for s in sessions if s["id"] not in reviewed]

        if first_pass:
            reviewed.update(s["id"] for s in sessions)
            save_state(reviewed)
            print(f"watcher: baseline — {len(sessions)} existing session(s) "
                  f"marked reviewed, no notifications")
            first_pass = False
        else:
            for session in new:
                result = review_one(session, args.events_dir, backend)
                if result is None:
                    print(f"watcher: session {session['id'][:8]} — events "
                          "unavailable (rotated?), marked reviewed",
                          file=sys.stderr)
                else:
                    print(f"watcher: reviewed {session['id'][:8]} "
                          f"({backend_label})")
                    if telegram:
                        try:
                            send_message(telegram, format_briefing(result))
                            print(f"watcher: briefing sent for "
                                  f"{session['id'][:8]}")
                        except TelegramConfigError as exc:
                            print(f"watcher: telegram send failed — {exc}",
                                  file=sys.stderr)
                reviewed.add(session["id"])
                save_state(reviewed)

        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
