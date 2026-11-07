"""Tests for the broker: leases, ledger atomicity, policy, server logic."""
from __future__ import annotations

import concurrent.futures
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker import leases, policy  # noqa: E402
from broker.ledger import Ledger  # noqa: E402
from broker.server import Broker  # noqa: E402

KEY = b"\x33" * 32
AGENT_UID = 1001  # ai-muse in the tests


def make_lease(op_class="systemctl-restart", units=("azt-test.service",),
              ttl=7200.0, max_uses=1, principal="ai-muse",
              lease_id="LSE-1", request_id="REQ-1") -> tuple[str, dict]:
    scope = {"units": list(units)}
    token = leases.mint_lease(KEY, lease_id=lease_id, request_id=request_id,
                              principal=principal, op_class=op_class,
                              scope=scope, ttl_seconds=ttl,
                              max_uses=max_uses)
    return token, {"lease_id": lease_id, "scope": scope}


class LeaseTest(unittest.TestCase):
    def test_round_trip(self):
        token, _ = make_lease()
        payload = leases.verify_lease(KEY, token)
        self.assertEqual(payload["op_class"], "systemctl-restart")
        self.assertEqual(payload["scope"]["units"], ["azt-test.service"])
        self.assertEqual(payload["principal"], "ai-muse")

    def test_tampered_payload_rejected(self):
        token, _ = make_lease()
        body, _, sig = token.partition(".")
        # decode payload, tamper, re-encode without re-signing
        import base64
        payload = json.loads(base64.urlsafe_b64decode(
            body + "=" * (-len(body) % 4)))
        payload["scope"]["units"] = ["other.service"]
        tampered = base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True).encode()).rstrip(b"=").decode()
        with self.assertRaises(leases.LeaseError):
            leases.verify_lease(KEY, f"{tampered}.{sig}")

    def test_wrong_key_rejected(self):
        token, _ = make_lease()
        with self.assertRaises(leases.LeaseError):
            leases.verify_lease(b"\x44" * 32, token)

    def test_expired(self):
        token, _ = make_lease(ttl=-10)
        with self.assertRaises(leases.LeaseError):
            leases.verify_lease(KEY, token)


class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite3",
                                                delete=False)
        self.tmp.close()
        self.ledger = Ledger(self.tmp.name)

    def tearDown(self):
        Path(self.tmp.name).unlink(missing_ok=True)

    def test_consume_up_to_max_then_exhausted(self):
        self.assertEqual(self.ledger.consume_use("L1", 2), 1)
        self.assertEqual(self.ledger.consume_use("L1", 2), 2)
        self.assertIsNone(self.ledger.consume_use("L1", 2))

    def test_concurrent_double_redeem_fails_exactly_one(self):
        # 20 concurrent attempts on a 3-use lease: exactly 3 succeed
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(
                lambda _: self.ledger.consume_use("L2", 3), range(20)))
        succeeded = sorted(r for r in results if r is not None)
        self.assertEqual(succeeded, [1, 2, 3])

    def test_max_uses_zero_rejected(self):
        self.assertIsNone(self.ledger.consume_use("L3", 0))


class PolicyTest(unittest.TestCase):
    def test_build_command_valid(self):
        cmd = policy.build_command("systemctl-restart",
                                   {"unit": "training-web.service"})
        self.assertEqual(cmd, ["systemctl", "restart", "training-web.service"])

    def test_unit_injection_rejected(self):
        for bad in ("../etc/passwd.service", "a;rm.service",
                    "x.service\n", "", "weird name.service"):
            with self.assertRaises(policy.PolicyError):
                policy.build_command("systemctl-restart", {"unit": bad})

    def test_unknown_class_rejected(self):
        with self.assertRaises(policy.PolicyError):
            policy.build_command("rm-rf", {"unit": "x.service"})

    def test_lease_covers(self):
        token, payload = make_lease(units=("a.service", "b.service"))
        verified = leases.verify_lease(KEY, token)
        self.assertTrue(policy.lease_covers(
            verified, "systemctl-restart", {"unit": "a.service"}))
        self.assertFalse(policy.lease_covers(
            verified, "systemctl-restart", {"unit": "c.service"}))
        self.assertFalse(policy.lease_covers(
            verified, "systemctl-stop", {"unit": "a.service"}))


class BrokerLogicTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite3",
                                                delete=False)
        self.tmp.close()
        self.ledger = Ledger(self.tmp.name)
        self.broker = Broker(KEY, self.ledger)

    def tearDown(self):
        Path(self.tmp.name).unlink(missing_ok=True)

    def test_run_without_lease_denies_with_denial_id_and_hint(self):
        response = self.broker.handle(
            {"op": "run", "op_class": "systemctl-restart",
             "args": {"unit": "azt-test.service"}}, AGENT_UID)
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["reason"], "no-lease")
        self.assertTrue(response["denial_id"].startswith("DN-"))
        self.assertIn("request_approval", response["hint"])
        self.assertIn(response["denial_id"], response["hint"])
        # the denial is recorded as evidence
        row = self.ledger.conn.execute(
            "SELECT reason FROM denials WHERE denial_id = ?",
            (response["denial_id"],)).fetchone()
        self.assertEqual(row[0], "no-lease")

    def test_non_agent_uid_denied(self):
        response = self.broker.handle(
            {"op": "run", "op_class": "systemctl-restart",
             "args": {"unit": "azt-test.service"}}, 1000)
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["reason"], "not-authorized")

    def test_valid_lease_executes_and_consumes(self):
        token, payload = make_lease(max_uses=2)
        with mock.patch("broker.server.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="",
                                         stderr="")
            response = self.broker.handle(
                {"op": "run", "op_class": "systemctl-restart",
                 "args": {"unit": "azt-test.service"}, "lease": token},
                AGENT_UID)
        self.assertEqual(response["status"], "executed")
        self.assertEqual(response["use_no"], 1)
        run.assert_called_once_with(
            ["systemctl", "restart", "azt-test.service"],
            capture_output=True, text=True, timeout=60)
        # second use succeeds, third exhausts
        with mock.patch("broker.server.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="",
                                         stderr="")
            r2 = self.broker.handle(
                {"op": "run", "op_class": "systemctl-restart",
                 "args": {"unit": "azt-test.service"}, "lease": token},
                AGENT_UID)
            r3 = self.broker.handle(
                {"op": "run", "op_class": "systemctl-restart",
                 "args": {"unit": "azt-test.service"}, "lease": token},
                AGENT_UID)
        self.assertEqual(r2["use_no"], 2)
        self.assertEqual(r3["status"], "denied")
        self.assertEqual(r3["reason"], "uses-exhausted")

    def test_out_of_scope_lease_denied(self):
        token, _ = make_lease(units=("other.service",))
        response = self.broker.handle(
            {"op": "run", "op_class": "systemctl-restart",
             "args": {"unit": "azt-test.service"}, "lease": token},
            AGENT_UID)
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["reason"], "out-of-scope")

    def test_lease_for_other_principal_denied(self):
        token, _ = make_lease(principal="someone-else")
        response = self.broker.handle(
            {"op": "run", "op_class": "systemctl-restart",
             "args": {"unit": "azt-test.service"}, "lease": token},
            AGENT_UID)
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["reason"], "lease-not-for-you")


if __name__ == "__main__":
    unittest.main()
