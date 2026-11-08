"""agent-zerotrust MCP server — the agent-facing approval interface.

A minimal, dependency-free MCP server (JSON-RPC 2.0 over HTTP, stateless
mode) exposing:

    request_approval(action, justification) -> pending view (async)
    get_approval(request_id)                 -> current status/decision

Listens on 127.0.0.1 only — the agent reaches it over its own SSH
session (port forwarding: ssh -L 8930:127.0.0.1:8930 ...), so the
control traffic flows through the audited path.

A background thread polls Telegram callbacks so [承認]/[拒否] button taps
record the human decision; get_approval then returns it to the agent.

Run:  python -m approvals.mcp_server            (default port 8930)
      PORT=9000 python -m approvals.mcp_server
"""
from __future__ import annotations

import json
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import service, store
from evidence.telegram import (TelegramConfigError, answer_callback,
                               edit_message, get_updates, load_config)
from workers import gateway as worker_gateway

REPO = __import__("pathlib").Path(__file__).resolve().parents[1]
PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "agent-zerotrust-approvals", "version": "0.1.0"}

TOOLS = [
    {
        "name": "request_approval",
        "description": (
            "Request human approval for an action that needs an exception. "
            "Returns immediately with status=pending; poll get_approval for "
            "the human's decision. The action and justification are your "
            "untrusted claim — describe exactly what you intend to run and "
            "why it is needed for the user's task."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string",
                           "description": "the exact action to approve"},
                "justification": {"type": "string",
                                   "description": "why it is needed"},
                "op_class": {"type": "string",
                              "description": "structured op: "
                              "systemctl-restart | systemctl-start | "
                              "systemctl-stop (enables lease redemption "
                              "on approval)"},
                "op_args": {"type": "object",
                            "description": "e.g. {\"unit\": "
                            "\"training-web.service\"}"},
                "denial_id": {"type": "string",
                              "description": "the DN-... id from the "
                              "broker denial, if this request follows one"},
                "max_uses": {"type": "integer",
                              "description": "proposed lease use count "
                              "(1-10, default 1)"},
            },
            "required": ["action", "justification"],
        },
    },
    {
        "name": "get_approval",
        "description": "Get the current status of an approval request.",
        "inputSchema": {
            "type": "object",
            "properties": {"request_id": {"type": "string"}},
            "required": ["request_id"],
        },
    },
    {
        "name": "list_worker_agents",
        "description": (
            "List available local CLI coding agents on the protected host (codex, dsh, "
            "opencode, commandcode, vibe, agy) and supported targets "
            "(linux or windows via ssh/mounts)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "dispatch_worker_task",
        "description": (
            "Delegate a coding/system task to a local CLI agent on the protected host. "
            "Use target='windows' when you want the worker agent to operate "
            "on the Windows host (with full GPU & project "
            "ownership via `ssh windows` or `/mnt/Win-*`). Use target='linux' "
            "for local projects. Every task is safety-screened, audited, and "
            "notifies the owner on Telegram."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent": {
                    "type": "string",
                    "description": "codex | dsh | opencode | commandcode | vibe | agy",
                },
                "instruction": {
                    "type": "string",
                    "description": "Clear task instruction for the worker agent",
                },
                "target": {
                    "type": "string",
                    "description": "linux (default) or windows",
                },
                "workdir": {
                    "type": "string",
                    "description": "Working directory on the protected host (default /mnt/ssd2tb/projects)",
                },
                "wait_seconds": {
                    "type": "integer",
                    "description": "Seconds to wait before returning running status (default 25, max 120)",
                },
            },
            "required": ["agent", "instruction"],
        },
    },
    {
        "name": "get_worker_task",
        "description": "Get status and output preview of a dispatched worker task.",
        "inputSchema": {
            "type": "object",
            "properties": {"task_id": {"type": "string"}},
            "required": ["task_id"],
        },
    },
]


def _tool_result(payload: dict) -> dict:
    return {"content": [{"type": "text",
                         "text": json.dumps(payload, ensure_ascii=False)}],
            "structuredContent": payload}


def dispatch(method: str, params: dict, env: dict,
             source_ip: str | None = None) -> tuple[dict | None, int]:
    """Returns (result, http_status). None result = no response body."""
    if method == "initialize":
        return {"protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO}, 200
    if method == "notifications/initialized":
        return None, 202
    if method == "ping":
        return {}, 200
    if method == "tools/list":
        return {"tools": TOOLS}, 200
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "request_approval":
            action = str(args.get("action", "")).strip()
            justification = str(args.get("justification", "")).strip()
            if not action or not justification:
                return _error_result(
                    "action and justification are required"), 200
            op_class = str(args.get("op_class", "")).strip()
            op_args = args.get("op_args") or {}
            denial_id = str(args.get("denial_id", "")).strip()
            try:
                max_uses = int(args.get("max_uses", 1))
            except (TypeError, ValueError):
                max_uses = 1
            try:
                view = service.request_approval(
                    action, justification,
                    env["admin_password"], env["events_dir"],
                    op_class=op_class, op_args=op_args,
                    denial_id=denial_id, max_uses=max_uses)
            except ValueError as exc:
                return _error_result(str(exc)), 200
            return _tool_result(view), 200
        if name == "get_approval":
            rid = str(args.get("request_id", "")).strip()
            view = store.get_request(rid)
            if view is None:
                return _tool_result({"request_id": rid,
                                      "status": "unknown"}), 200
            return _tool_result(view), 200
        if name == "list_worker_agents":
            agents = worker_gateway.discover_agents()
            return _tool_result({
                "available_agents": sorted(agents.keys()),
                "targets": ["linux", "windows"],
                "allowed_linux_roots": list(worker_gateway.ALLOWED_LINUX_ROOTS),
            }), 200
        if name == "dispatch_worker_task":
            agent = str(args.get("agent", "")).strip()
            instruction = str(args.get("instruction", "")).strip()
            if not agent or not instruction:
                return _error_result("agent and instruction are required"), 200
            target = str(args.get("target", "linux")).strip() or "linux"
            workdir = str(args.get("workdir", "/mnt/ssd2tb/projects")).strip() or "/mnt/ssd2tb/projects"
            try:
                wait_s = int(args.get("wait_seconds", 25))
            except (TypeError, ValueError):
                wait_s = 25
            try:
                view = worker_gateway.dispatch_task(
                    agent=agent,
                    instruction=instruction,
                    target=target,
                    workdir=workdir,
                    wait_seconds=wait_s,
                    source_ip=source_ip,
                )
            except ValueError as exc:
                return _error_result(str(exc)), 200
            return _tool_result(view), 200
        if name == "get_worker_task":
            tid = str(args.get("task_id", "")).strip()
            view = worker_gateway.get_task(tid)
            if view is None:
                return _tool_result({"task_id": tid, "status": "unknown"}), 200
            return _tool_result(view), 200
        return _error_result(f"unknown tool: {name}"), 200
    return None, 404


def _error_result(message: str) -> dict:
    return {"content": [{"type": "text", "text": message}], "isError": True}


class Handler(BaseHTTPRequestHandler):
    env: dict = {}

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"agent-zerotrust MCP approvals server\n")

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != "/mcp":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            message = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._respond(400, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32700,
                                          "message": "parse error"}})
            return
        method = message.get("method", "")
        is_request = "id" in message
        try:
            result, status = dispatch(method, message.get("params") or {},
                                      self.env,
                                      source_ip=self.client_address[0])
        except Exception as exc:  # never leak internals
            result = {"error": {"code": -32603,
                                "message": "internal error"}}
            status = 200
            print(f"mcp: dispatch error in {method}: "
                  f"{type(exc).__name__}", file=sys.stderr)
        if not is_request:
            self.send_response(202)
            self.end_headers()
            return
        body = {"jsonrpc": "2.0", "id": message["id"]}
        if result is not None:
            body["result"] = result
        self._respond(status, body)

    def _respond(self, status: int, body: dict):
        payload = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        print(f"mcp: {self.address_string()} {fmt % args}", file=sys.stderr)


def callback_poller(config):
    """Poll Telegram callbacks; record decisions; update the message."""
    offset = None
    while True:
        try:
            if offset is None:
                # fast-forward past history on startup
                updates = get_updates(config, offset=-1, timeout=0)
            else:
                updates = get_updates(config, offset, timeout=25)
        except (TelegramConfigError, Exception):
            import time
            time.sleep(10)
            continue
        for upd in updates:
            offset = max(offset or 0, upd["update_id"] + 1)
            cb = upd.get("callback_query")
            if not cb:
                continue
            data = cb.get("data", "")
            message = cb.get("message") or {}
            chat_id = message.get("chat", {}).get("id")
            message_id = message.get("message_id")
            try:
                decision, rid = data.split(":", 1)
            except ValueError:
                continue
            if decision not in ("approve", "deny"):
                continue
            try:
                view, changed = service.decide(rid, "approved"
                                                if decision == "approve"
                                                else "denied")
            except Exception as exc:
                print(f"mcp: decide failed for {rid}: {type(exc).__name__}",
                      file=sys.stderr)
                try:
                    answer_callback(config, cb["id"],
                                    "内部エラーです。もう一度押してください。")
                except TelegramConfigError:
                    pass
                continue
            ja = {"approved": "✅ 承認されました",
                  "denied": "🚫 拒否されました",
                  "pending": "処理中…", "expired": "期限切れです",
                  "unknown": "リクエスト不明"}[view.get("status", "unknown")]
            try:
                answer_callback(config, cb["id"],
                                ja if changed else "処理済みです")
                if changed and chat_id and message_id:
                    edit_message(config, chat_id, message_id,
                                 f"{ja}\nリクエスト: {rid}")
            except TelegramConfigError:
                pass


def main() -> int:
    port = int(os.environ.get("APPROVAL_PORT", "8930"))
    admin_password = (REPO / "deploy/warpgate/state/admin-password.txt"
                      ).read_text().strip()
    Handler.env = {
        "admin_password": admin_password,
        "events_dir": "/mnt/hdd22/agent-zerotrust/evidence/tetragon",
    }
    try:
        config = load_config()
        threading.Thread(target=callback_poller, args=(config,),
                         daemon=True).start()
        print("mcp: telegram callback poller started", file=sys.stderr)
    except TelegramConfigError as exc:
        print(f"mcp: telegram not configured — {exc}", file=sys.stderr)

    bind = os.environ.get("APPROVAL_BIND", "127.0.0.1")
    server = ThreadingHTTPServer((bind, port), Handler)
    print(f"mcp: approvals server on {bind}:{port}", file=sys.stderr)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
