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
]


def _tool_result(payload: dict) -> dict:
    return {"content": [{"type": "text",
                         "text": json.dumps(payload, ensure_ascii=False)}],
            "structuredContent": payload}


def dispatch(method: str, params: dict, env: dict) -> tuple[dict | None, int]:
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
            view = service.request_approval(
                action, justification,
                env["admin_password"], env["events_dir"])
            return _tool_result(view), 200
        if name == "get_approval":
            rid = str(args.get("request_id", "")).strip()
            view = store.get_request(rid)
            if view is None:
                return _tool_result({"request_id": rid,
                                      "status": "unknown"}), 200
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
                                      self.env)
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
            view, changed = service.decide(rid, "approved"
                                            if decision == "approve"
                                            else "denied")
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
        "events_dir": str(REPO / "deploy/tetragon/state/events"),
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
