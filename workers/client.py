"""azt-worker — CLI client for the MCP Worker & Approval Gateway.

Allows an SSH-connected agent (running as `ai-muse` with zero API keys or
host credentials) to invoke the local Worker Gateway and Approval Gateway
over localhost HTTP (:8930/mcp).

Usage:
    azt-worker agents
    azt-worker run <agent> "<instruction>" [--target linux|windows] [--workdir DIR] [--wait SEC]
    azt-worker status <task_id>
    azt-worker request-approval "<action>" "<justification>" [--op-class CLS] [--unit UNIT] [--denial-id ID]
    azt-worker check-approval <request_id>
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request

MCP_URL = os.environ.get("AZT_MCP_URL", "http://127.0.0.1:8930/mcp")


def call_mcp_tool(name: str, arguments: dict, timeout: int = 150) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    req = urllib.request.Request(
        MCP_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    result = body.get("result") or {}
    if result.get("isError"):
        text = (result.get("content") or [{}])[0].get("text", "MCP error")
        return {"status": "error", "error": text}
    return result.get("structuredContent") or result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("agents", help="List available worker CLI agents")

    p_run = sub.add_parser("run", help="Dispatch a task to a worker agent")
    p_run.add_argument("agent", help="codex | dsh | opencode | commandcode | vibe | agy")
    p_run.add_argument("instruction", help="Task instruction")
    p_run.add_argument("--target", default="linux", choices=["linux", "windows"])
    p_run.add_argument("--workdir", default="/mnt/ssd2tb/projects")
    p_run.add_argument("--wait", type=int, default=45, help="Seconds to wait (max 120)")

    p_st = sub.add_parser("status", help="Get status/output of a worker task")
    p_st.add_argument("task_id")

    p_req = sub.add_parser("request-approval", help="Request human approval via Telegram")
    p_req.add_argument("action")
    p_req.add_argument("justification")
    p_req.add_argument("--op-class", default="")
    p_req.add_argument("--unit", default="")
    p_req.add_argument("--denial-id", default="")
    p_req.add_argument("--max-uses", type=int, default=1)

    p_chk = sub.add_parser("check-approval", help="Check status/lease of an approval request")
    p_chk.add_argument("request_id")

    args = ap.parse_args(argv)
    if args.cmd == "agents":
        out = call_mcp_tool("list_worker_agents", {})
    elif args.cmd == "run":
        out = call_mcp_tool(
            "dispatch_worker_task",
            {
                "agent": args.agent,
                "instruction": args.instruction,
                "target": args.target,
                "workdir": args.workdir,
                "wait_seconds": args.wait,
            },
            timeout=max(60, args.wait + 30),
        )
    elif args.cmd == "status":
        out = call_mcp_tool("get_worker_task", {"task_id": args.task_id})
    elif args.cmd == "request-approval":
        op_args = {"unit": args.unit} if args.unit else {}
        out = call_mcp_tool(
            "request_approval",
            {
                "action": args.action,
                "justification": args.justification,
                "op_class": args.op_class,
                "op_args": op_args,
                "denial_id": args.denial_id,
                "max_uses": args.max_uses,
            },
        )
    else:
        out = call_mcp_tool("get_approval", {"request_id": args.request_id})

    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 1 if out.get("status") in ("error", "blocked", "failed") else 0


if __name__ == "__main__":
    raise SystemExit(main())
