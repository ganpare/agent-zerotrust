"""Deterministic GuardianBackend — the AI-optional floor.

Implements the same protocol as the LLM backends (guardian.backends) but
uses only rules. Advisory only, per SR10: it can raise scrutiny (flags,
escalate suggestions) but never issues grants, tiers, or decisions.

Semantic claim-vs-evidence comparison is the LLM backend's job; this
backend does what rules can and says so in its uncertainties.
"""
from __future__ import annotations

SENSITIVE_READ = (
    "/etc/shadow", "/etc/sudoers", "/etc/ssh/", "/.ssh/", ".env",
    "canary", ".bash_history", "_history", "/root/",
)
PERSISTENCE_WRITE = (
    "/etc/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/",
    "/usr/local/sbin/", "/var/log/", "/.ssh/",
)


def _is_private(dest: str) -> bool:
    """Loopback, RFC1918, link-local, and the tailnet CGNAT range."""
    host = dest.rsplit(":", 1)[0] if dest.count(":") == 1 else dest
    if host.startswith(("127.", "10.", "192.168.", "169.254.")):
        return True
    if host.startswith("172."):
        try:
            second = int(host.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            pass
    if host.startswith("100."):
        try:
            if 64 <= int(host.split(".")[1]) <= 127:  # 100.64.0.0/10 (tailnet)
                return True
        except (ValueError, IndexError):
            pass
    return host in ("::1", "localhost")


class RuleBackend:
    """Rule-based assessment: flags what the evidence shows, nothing more."""

    @staticmethod
    def _flag(flags: list, flagged_ids: list, eid: str, message: str):
        flagged_ids.append(eid)
        if message not in flags:
            flags.append(message)

    def assess(self, case: dict) -> dict:
        flags: list[str] = []
        flagged_ids: list[str] = []
        for ev in case.get("evidence", []):
            action = ev.get("action", "")
            eid = ev.get("event_id", "")
            if action.startswith("read ") and any(
                    p in action[5:] for p in SENSITIVE_READ):
                self._flag(flags, flagged_ids, eid,
                           f"sensitive file read: {action[5:]}")
            elif action.startswith("write ") and any(
                    p in action[6:] for p in PERSISTENCE_WRITE):
                self._flag(flags, flagged_ids, eid,
                           f"persistence-relevant write: {action[6:]}")
            elif action == "connect unix-socket":
                continue  # local IPC, not egress
            elif action.startswith("connect ") and not _is_private(action[8:]):
                self._flag(flags, flagged_ids, eid,
                           f"external connect: {action[8:]}")

        execs = sum(1 for e in case.get("evidence", [])
                   if e.get("action", "").startswith("exec "))
        reads = sum(1 for e in case.get("evidence", [])
                    if e.get("action", "").startswith("read "))
        connects = sum(1 for e in case.get("evidence", [])
                       if e.get("action", "").startswith("connect "))

        claim = case.get("claim", {})
        post_hoc = "no agent claim" in claim.get("purpose", "").lower()
        uncertainties = ["Deterministic rule backend — no semantic analysis."]
        if post_hoc:
            uncertainties.append(
                "No agent claim recorded — consistency cannot be assessed.")

        summary = (
            f"{execs} command(s) executed; {reads} file read(s); "
            f"{connects} connect(s). "
            + (f"{len(flags)} risk flag(s)." if flags else "No rule flags.")
        )

        return {
            "consistency": "insufficient_evidence" if post_hoc else "partial",
            "summary": summary,
            "uncertainties": uncertainties[:5],
            "evidence_ids": flagged_ids[:20],
            "suggested_next_step": "escalate" if flags else "review",
        }
