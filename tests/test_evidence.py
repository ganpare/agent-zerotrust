"""Tests for the evidence package: correlation, case building, rule backend."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian.evaluator import evaluate  # noqa: E402
from evidence.case_builder import build_case  # noqa: E402
from evidence.correlate import correlate_session  # noqa: E402
from evidence.rule_backend import RuleBackend, _is_private  # noqa: E402


def exec_event(exec_id, parent_id, binary, args, uid, t, parent_binary="/usr/sbin/sshd"):
    return {
        "time": t,
        "process_exec": {
            "process": {
                "exec_id": exec_id, "pid": 100, "uid": uid, "auid": uid,
                "binary": binary, "arguments": args,
                "parent_exec_id": parent_id, "start_time": t,
            },
            "parent": {"exec_id": parent_id, "pid": 99, "uid": 0,
                       "binary": parent_binary, "arguments": "",
                       "parent_exec_id": "sshd-root"},
        },
    }


def kprobe_event(exec_id, parent_id, binary, t, function, args, policy="p"):
    return {
        "time": t,
        "process_kprobe": {
            "process": {"exec_id": exec_id, "pid": 101, "uid": 1001,
                        "binary": binary, "arguments": "",
                        "parent_exec_id": parent_id},
            "function_name": function, "args": args, "policy_name": policy,
        },
    }


SESSION = {
    "id": "s1", "username": "muse",
    "started": "2026-11-07T10:00:00Z", "ended": "2026-11-07T10:00:10Z",
    "target_sessions": [{"started": "2026-11-07T10:00:00Z",
                         "ended": "2026-11-07T10:00:10Z",
                         "target": {"name": "<PROTECTED_HOST>-local"}}],
}

EVENTS = [
    # decoy 1: another bash-under-sshd, OUTSIDE the session window
    exec_event("e0", "p0", "/bin/bash", "-c decoy", 1001, "2026-11-07T09:00:00Z"),
    # decoy 2: a uid-1001 process in-window but NOT under the session shell
    exec_event("e9", "sysd", "/usr/bin/pipewire", "", 1001, "2026-11-07T10:00:03Z",
               parent_binary="/usr/lib/systemd/systemd"),
    # the session shell (seed)
    exec_event("e1", "sshd1", "/bin/bash", "-c session", 1001, "2026-11-07T10:00:01Z"),
    # children of the shell
    exec_event("e2", "e1", "/usr/bin/cat", "/home/ai-muse/canary-secret.txt",
               1001, "2026-11-07T10:00:02Z"),
    exec_event("e3", "e1", "/usr/bin/curl", "http://93.184.216.34",
               1001, "2026-11-07T10:00:04Z"),
    # kprobe: canary read by the cat process
    kprobe_event("e2", "e1", "/usr/bin/cat", "2026-11-07T10:00:02Z",
                 "security_file_permission",
                 [{"file_arg": {"path": "/home/ai-muse/canary-secret.txt"}},
                  {"int_arg": 4}],
                 policy="agent-sensitive-file-access"),
    # kprobe: external connect by the curl process
    kprobe_event("e3", "e1", "/usr/bin/curl", "2026-11-07T10:00:04Z",
                 "security_socket_connect",
                 [{"sockaddr_arg": {"family": "AF_INET",
                                    "addr": "93.184.216.34", "port": 80}}],
                 policy="agent-outbound-connects"),
    # kprobe: tailnet connect (private — must NOT be flagged)
    kprobe_event("e3", "e1", "/usr/bin/curl", "2026-11-07T10:00:05Z",
                 "security_socket_connect",
                 [{"sockaddr_arg": {"family": "AF_INET",
                                    "addr": "<PROTECTED_HOST_IP>", "port": 22}}],
                 policy="agent-outbound-connects"),
    # kprobe: local unix-socket connect (IPC — must NOT be flagged as egress)
    kprobe_event("e3", "e1", "/usr/bin/curl", "2026-11-07T10:00:06Z",
                 "security_socket_connect",
                 [{"sockaddr_arg": {"family": "AF_UNIX", "addr": "invalid IP"}}],
                 policy="agent-outbound-connects"),
]


class CorrelateTest(unittest.TestCase):
    def test_selects_the_session_subtree_and_excludes_decoys(self):
        correlated = correlate_session(SESSION, EVENTS)
        self.assertIsNotNone(correlated)
        binaries = {e["process_exec"]["process"]["binary"]
                    for e in correlated["execs"]}
        ids = {e["process_exec"]["process"]["exec_id"]
               for e in correlated["execs"]}
        self.assertEqual(binaries, {"/bin/bash", "/usr/bin/cat", "/usr/bin/curl"})
        self.assertNotIn("e0", ids)  # outside the window
        self.assertNotIn("e9", ids)  # uid matches but not under the shell
        self.assertEqual(len(correlated["kprobes"]), 4)

    def test_returns_none_when_no_shell_in_window(self):
        late = {**SESSION, "started": "2026-11-07T11:00:00Z",
               "ended": "2026-11-07T11:00:10Z",
               "target_sessions": [{"started": "2026-11-07T11:00:00Z",
                                    "ended": "2026-11-07T11:00:10Z"}]}
        self.assertIsNone(correlate_session(late, EVENTS))


class CaseAndAssessmentTest(unittest.TestCase):
    def test_case_builds_and_assessment_flags_canary_and_external_connect(self):
        correlated = correlate_session(SESSION, EVENTS)
        case = build_case(SESSION, correlated)
        result = evaluate(case, RuleBackend())

        self.assertEqual(result["assessment"]["status"], "complete")
        actions = [e["action"] for e in result["evidence"]]
        self.assertIn("read /home/ai-muse/canary-secret.txt", actions)
        self.assertIn("connect 93.184.216.34:80", actions)
        self.assertIn("ssh session via warpgate as ai-muse", actions)

        # the flagged evidence: canary read + external connect, but the
        # tailnet connect must NOT be flagged
        flagged = {eid: action for eid, action in
                   ((e["event_id"], e["action"]) for e in result["evidence"])
                   if eid in result["assessment"]["evidence_ids"]}
        flagged_actions = set(flagged.values())
        self.assertIn("read /home/ai-muse/canary-secret.txt", flagged_actions)
        self.assertIn("connect 93.184.216.34:80", flagged_actions)
        self.assertNotIn("connect <PROTECTED_HOST_IP>:22", flagged_actions)
        self.assertNotIn("connect unix-socket", flagged_actions)

        self.assertEqual(result["assessment"]["suggested_next_step"], "escalate")
        # post-hoc review: no claim to compare against
        self.assertEqual(result["assessment"]["consistency"],
                         "insufficient_evidence")
        self.assertTrue(result["decision_required"])

    def test_guardian_schema_accepts_the_case(self):
        # evaluate() runs _case() validation (sizes, uniqueness, tiers)
        # and would raise on any violation — reaching "complete" proves it.
        correlated = correlate_session(SESSION, EVENTS)
        result = evaluate(build_case(SESSION, correlated), RuleBackend())
        self.assertEqual(result["assessment"]["status"], "complete")


class PrivateDestinationTest(unittest.TestCase):
    def test_private_ranges(self):
        self.assertTrue(_is_private("<PROTECTED_HOST_IP>:22"))   # tailnet CGNAT
        self.assertTrue(_is_private("<LAN_IP>:22"))   # RFC1918
        self.assertTrue(_is_private("10.1.2.3:80"))
        self.assertTrue(_is_private("172.20.1.5:80"))
        self.assertTrue(_is_private("127.0.0.1:53"))
        self.assertFalse(_is_private("93.184.216.34:80"))
        self.assertFalse(_is_private("8.8.8.8:53"))


if __name__ == "__main__":
    unittest.main()
