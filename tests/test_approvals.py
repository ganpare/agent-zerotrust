"""Tests for the approval service: store, decision flow, MCP dispatch."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from approvals import mcp_server, service, store  # noqa: E402


class StoreTest(unittest.TestCase):
    def setUp(self):
        # redirect the store to a temp file
        self.tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False)
        self.tmp.close()
        store.STORE_PATH = Path(self.tmp.name)

    def tearDown(self):
        Path(self.tmp.name).unlink(missing_ok=True)

    def test_request_lifecycle_pending_decided(self):
        store.create_request("REQ-1", "restart nginx", "deploy fix", "s1")
        view = store.get_request("REQ-1")
        self.assertEqual(view["status"], "pending")
        self.assertEqual(view["action"], "restart nginx")

        store.add_decision("REQ-1", "approved", "telegram:human")
        view = store.get_request("REQ-1")
        self.assertEqual(view["status"], "approved")
        self.assertEqual(view["decision"]["decision"], "approved")

    def test_expired_request(self):
        with mock.patch.object(store, "create_request",
                                side_effect=self._create_expired):
            store.create_request("REQ-2", "x", "y", "s")
        view = store.get_request("REQ-2")
        self.assertEqual(view["status"], "expired")

    @staticmethod
    def _create_expired(rid, action, just, sid, ttl_seconds=7200):
        # simulate a request created in the past
        import time
        now = time.time() - 100
        store._append({"type": "request", "request_id": rid,
                       "action": action, "justification": just,
                       "session_id": sid, "created_at": now,
                       "expires_at": now + 10, "claim_version": 1})
        return {}

    def test_unknown_request(self):
        self.assertIsNone(store.get_request("REQ-nope"))


class DecideTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False)
        self.tmp.close()
        store.STORE_PATH = Path(self.tmp.name)

    def tearDown(self):
        Path(self.tmp.name).unlink(missing_ok=True)

    def test_decide_is_idempotent(self):
        store.create_request("REQ-3", "a", "j", "s")
        view1, changed1 = service.decide("REQ-3", "approved")
        self.assertEqual(view1["status"], "approved")
        self.assertTrue(changed1)
        view2, changed2 = service.decide("REQ-3", "denied")
        self.assertEqual(view2["status"], "approved")  # unchanged
        self.assertFalse(changed2)

    def test_decide_rejects_invalid(self):
        with self.assertRaises(ValueError):
            service.decide("REQ-x", "maybe")


class McpDispatchTest(unittest.TestCase):
    ENV = {"admin_password": "pw", "events_dir": "/nonexistent"}

    def test_initialize(self):
        result, status = mcp_server.dispatch("initialize", {}, self.ENV)
        self.assertEqual(status, 200)
        self.assertEqual(result["serverInfo"]["name"],
                         "agent-zerotrust-approvals")
        self.assertIn("tools", result["capabilities"])

    def test_tools_list_shape(self):
        result, _ = mcp_server.dispatch("tools/list", {}, self.ENV)
        names = {t["name"] for t in result["tools"]}
        self.assertEqual(names, {"request_approval", "get_approval"})
        for tool in result["tools"]:
            self.assertIn("inputSchema", tool)
            self.assertIn("required", tool["inputSchema"])

    def test_request_approval_requires_both_fields(self):
        params = {"name": "request_approval",
                  "arguments": {"action": "x"}}  # justification missing
        result, _ = mcp_server.dispatch("tools/call", params, self.ENV)
        self.assertTrue(result.get("isError"))

    def test_unknown_tool(self):
        params = {"name": "nope", "arguments": {}}
        result, _ = mcp_server.dispatch("tools/call", params, self.ENV)
        self.assertTrue(result.get("isError"))


if __name__ == "__main__":
    unittest.main()
