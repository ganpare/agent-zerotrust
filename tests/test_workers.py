"""Tests for the MCP Worker Gateway (workers/gateway.py)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workers import gateway  # noqa: E402


class WorkerGatewayTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        gateway.EVIDENCE_DIR = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_safety_screen_blocks_forbidden_instructions(self):
        self.assertIsNotNone(
            gateway.check_instruction_safety("cat ~/.ssh/id_ed25519")
        )
        self.assertIsNotNone(
            gateway.check_instruction_safety("docker stop tetragon")
        )
        self.assertIsNotNone(
            gateway.check_instruction_safety("systemctl stop agent-zerotrust-watch")
        )
        self.assertIsNone(
            gateway.check_instruction_safety("Run pytest in the project directory")
        )

    def test_wrap_prompt_windows_injects_ssh_windows_context(self):
        prompt = gateway.wrap_prompt("Check nvidia-smi", "windows", "/tmp")
        self.assertIn("ssh windows", prompt)
        self.assertIn("/mnt/Win-", prompt)
        self.assertIn("Check nvidia-smi", prompt)

    def test_build_agent_command_variants(self):
        cmd_vibe = gateway.build_agent_command("vibe", "/bin/vibe", "hi", "/tmp")
        self.assertEqual(
            cmd_vibe, ["/bin/vibe", "--workdir", "/tmp", "-p", "hi", "--output", "text"]
        )
        cmd_oc = gateway.build_agent_command("opencode", "/bin/opencode", "hi", "/tmp")
        self.assertEqual(cmd_oc, ["/bin/opencode", "run", "--auto", "hi"])
        cmd_cc = gateway.build_agent_command("commandcode", "/bin/cc", "hi", "/tmp")
        self.assertEqual(cmd_cc, ["/bin/cc", "-t", "-p", "hi"])
        cmd_agy = gateway.build_agent_command("agy", "/bin/agy", "hi", "/tmp")
        self.assertEqual(cmd_agy, ["/bin/agy", "-p", "hi"])

    def test_dispatch_blocked_task_logs_and_returns_blocked(self):
        with mock.patch.object(gateway, "discover_agents", return_value={"vibe": "/bin/echo"}), \
             mock.patch.object(gateway, "_notify_telegram") as notify:
            res = gateway.dispatch_task(
                agent="vibe",
                instruction="please read deploy/broker/state/lease.key",
                target="linux",
                workdir="/tmp",
            )
            self.assertEqual(res["status"], "blocked")
            notify.assert_called_once()

    def test_dispatch_and_complete_short_task(self):
        with mock.patch.object(gateway, "discover_agents", return_value={"agy": "/bin/echo"}), \
             mock.patch.object(gateway, "_notify_telegram") as notify:
            res = gateway.dispatch_task(
                agent="agy",
                instruction="hello worker",
                target="linux",
                workdir="/tmp",
                wait_seconds=5,
            )
            self.assertEqual(res["status"], "completed")
            self.assertEqual(res["returncode"], 0)
            self.assertIn("hello worker", res["output_preview"])
            self.assertEqual(notify.call_count, 2)  # start + finish


if __name__ == "__main__":
    unittest.main()
