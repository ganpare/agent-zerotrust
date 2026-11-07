"""The privileged broker daemon.

Runs as root (systemd). Listens on a Unix socket; every connection is
identity-checked via SO_PEERCRED — the kernel-guaranteed caller uid.

Flow (per request):
  run:      validate the op against policy templates FIRST (no shell),
            then: no lease -> DENY with a machine-readable denial id and
            an MCP hint; valid lease -> verify signature, identity,
            scope, time window -> atomically consume a use slot ->
            execute EXACTLY the bound command -> record the result.
  status:   health check.

Every decision (denial or redemption) is recorded in the ledger. The
broker is the ONLY privileged door for the classes it mediates; the
agent user has no sudo, so nothing privileged happens outside this
funnel (T13: the broker itself is a high-value target — keep it small).
"""
from __future__ import annotations

import json
import os
import pwd
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

from . import leases as lease_mod
from . import policy
from .ledger import Ledger

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOCKET_PATH = os.environ.get("AZT_BROKER_SOCKET", "/run/agent-zerotrust/broker.sock")
KEY_PATH = os.environ.get(
    "AZT_LEASE_KEY", os.path.join(REPO, "deploy/broker/state/lease.key"))
LEDGER_PATH = os.environ.get(
    "AZT_LEDGER_PATH",
    "/mnt/hdd22/agent-zerotrust/evidence/broker/ledger.sqlite3")
AGENT_UID = int(os.environ.get("AZT_AGENT_UID", "1001"))  # ai-muse
EXEC_TIMEOUT = 60


def _peer_uid(conn: socket.socket) -> int:
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                            struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


def _uid_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f"uid-{uid}"


class Broker:
    def __init__(self, key: bytes, ledger: Ledger):
        self.key = key
        self.ledger = ledger

    def handle(self, request: dict, peer_uid: int) -> dict:
        op = request.get("op")
        if op == "status":
            return {"status": "ok", "broker": "agent-zerotrust", "v": 1}
        if op != "run":
            return {"status": "error", "error": f"unknown op: {op}"}

        op_class = str(request.get("op_class", ""))
        args = request.get("args") or {}
        lease_token = request.get("lease")

        if peer_uid != AGENT_UID:
            return self._deny(peer_uid, op_class, args, "not-authorized",
                              "only the agent user may use the broker")

        try:
            command = policy.build_command(op_class, args)
        except policy.PolicyError as exc:
            return self._deny(peer_uid, op_class, args, "invalid-op",
                              str(exc))

        if not lease_token:
            return self._deny(peer_uid, op_class, args, "no-lease",
                              "request approval via MCP (request_approval) "
                              "and redeem with the returned lease")

        try:
            payload = lease_mod.verify_lease(self.key, lease_token)
        except lease_mod.LeaseError as exc:
            return self._deny(peer_uid, op_class, args, "invalid-lease",
                              str(exc))

        principal = _uid_name(peer_uid)
        if payload["principal"] != principal:
            return self._deny(peer_uid, op_class, args, "lease-not-for-you",
                              f"lease is for {payload['principal']}")

        if not policy.lease_covers(payload, op_class, args):
            return self._deny(peer_uid, op_class, args, "out-of-scope",
                              f"lease covers {payload['scope']} only")

        use_no = self.ledger.consume_use(payload["lease_id"],
                                         payload["max_uses"])
        if use_no is None:
            return self._deny(peer_uid, op_class, args, "uses-exhausted",
                              "the lease has no uses left")

        # execute EXACTLY the bound command (rebuilt from the same
        # validated inputs — nothing from the lease or request is passed
        # to a shell)
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  timeout=EXEC_TIMEOUT)
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            rc, out, err = 124, "", f"command timed out after {EXEC_TIMEOUT}s"

        self.ledger.record_use(payload["lease_id"], use_no, command,
                               rc, out, err)
        return {
            "status": "executed" if rc == 0 else "exec-failed",
            "lease_id": payload["lease_id"],
            "request_id": payload.get("request_id"),
            "use_no": use_no,
            "command": command,
            "returncode": rc,
            "stdout": out[:2000],
            "stderr": err[:2000],
        }

    def _deny(self, peer_uid: int, op_class: str, args: dict,
              reason: str, detail: str) -> dict:
        denial_id = f"DN-{int(time.time())}-{uuid.uuid4().hex[:8]}"
        principal = _uid_name(peer_uid)
        self.ledger.record_denial(denial_id, principal, op_class, args,
                                  reason, detail)
        unit = args.get("unit", "")
        hint = (f"request approval via MCP: request_approval("
                f'action="systemctl {op_class.split("-", 1)[1]} {unit}", '
                f"justification=..., denial_id=\"{denial_id}\")")
        return {
            "status": "denied",
            "denial_id": denial_id,
            "reason": reason,
            "detail": detail,
            "hint": hint,
        }


def serve() -> int:
    with open(KEY_PATH, "rb") as f:
        key = f.read().strip()
    os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    ledger = Ledger(LEDGER_PATH)
    broker = Broker(key, ledger)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o666)  # connectable by all; SO_PEERCRED gates
    server.listen(16)
    print(f"broker: listening on {SOCKET_PATH} "
          f"(agent uid {AGENT_UID})", file=sys.stderr)

    def worker(conn: socket.socket):
        with conn:
            uid = _peer_uid(conn)
            try:
                data = conn.recv(65536)
                if not data:
                    return
                request = json.loads(data)
                response = broker.handle(request, uid)
            except (json.JSONDecodeError, ValueError) as exc:
                response = {"status": "error", "error": f"bad request: {exc}"}
            except Exception as exc:  # never leak internals
                response = {"status": "error",
                            "error": f"internal error: {type(exc).__name__}"}
            conn.sendall(json.dumps(response).encode())

    while True:
        conn, _ = server.accept()
        threading.Thread(target=worker, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    raise SystemExit(serve())
