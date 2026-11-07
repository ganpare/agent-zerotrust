"""azt-broker — the agent-facing CLI for privileged operations.

Thin client: connects to the broker's Unix socket, sends one JSON
request, prints the JSON response. Exit codes: 0 executed, 3 denied,
4 error. The broker enforces identity (SO_PEERCRED) — this binary holds
no secrets and grants nothing by itself.

Usage:
    azt-broker status
    azt-broker run <op-class> key=value ...          # try without a lease
    azt-broker redeem --lease <token> <op-class> key=value ...

Example:
    azt-broker run systemctl-restart unit=training-web.service
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys

SOCKET_PATH = os.environ.get("AZT_BROKER_SOCKET",
                             "/run/agent-zerotrust/broker.sock")


def _parse_args(pairs: list[str]) -> dict:
    args = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep:
            raise SystemExit(f"bad argument (want key=value): {pair}")
        args[key] = value
    return args


def _request(payload: dict) -> dict:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(90)
    client.connect(SOCKET_PATH)
    try:
        client.sendall(json.dumps(payload).encode())
        chunks = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        client.close()
    return json.loads(b"".join(chunks))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status")
    p_run = sub.add_parser("run")
    p_run.add_argument("op_class")
    p_run.add_argument("args", nargs="*")
    p_redeem = sub.add_parser("redeem")
    p_redeem.add_argument("--lease", required=True)
    p_redeem.add_argument("op_class")
    p_redeem.add_argument("args", nargs="*")

    parsed = ap.parse_args(argv)
    if parsed.cmd == "status":
        response = _request({"op": "status"})
    elif parsed.cmd == "run":
        response = _request({"op": "run", "op_class": parsed.op_class,
                             "args": _parse_args(parsed.args)})
    else:
        response = _request({"op": "run", "op_class": parsed.op_class,
                             "args": _parse_args(parsed.args),
                             "lease": parsed.lease})

    print(json.dumps(response, indent=2, ensure_ascii=False))
    if response.get("status") == "executed":
        return 0
    if response.get("status") == "denied":
        return 3
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
