"""Telegram notification adapter — the IDS alert channel.

Sends the session-review briefing to a Telegram chat via the Bot API.
Fixed template, redacted content by construction: the briefing carries
paths and commands (they ARE the evidence) but never file contents or
secret values (architecture §8.3: no secrets in the channel).

Configuration — environment first, then
deploy/monitoring/state/telegram.json (gitignored):
    TELEGRAM_BOT_TOKEN   from @BotFather
    TELEGRAM_CHAT_ID     the destination chat id

CLI:
    python -m evidence.telegram --send-test      # verify the setup
    python -m evidence.telegram --print-template  # show the message shape
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPO / "deploy/monitoring/state/telegram.json"
API_BASE = "https://api.telegram.org/bot"
MAX_LEN = 4096  # Telegram sendMessage limit


class TelegramConfigError(RuntimeError):
    pass


def load_config() -> dict:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token and CONFIG_PATH.exists():
        data = json.loads(CONFIG_PATH.read_text())
        token = token or data.get("bot_token")
        chat_id = chat_id or str(data.get("chat_id", ""))
    if not token or not chat_id:
        raise TelegramConfigError(
            "Telegram not configured. Create a bot with @BotFather, then set "
            "TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID (or write "
            f"{CONFIG_PATH} as {{\"bot_token\": \"...\", \"chat_id\": 123}})."
        )
    return {"bot_token": token, "chat_id": chat_id}


def split_message(text: str) -> list[str]:
    """Split into chunks that respect the Telegram length limit."""
    if len(text) <= MAX_LEN:
        return [text]
    chunks, current = [], ""
    for line in text.splitlines(keepends=True):
        if len(current) + len(line) > MAX_LEN - 200:
            chunks.append(current)
            current = line
        else:
            current += line
    if current:
        chunks.append(current)
    return chunks


def send_message(config: dict, text: str, reply_markup: dict | None = None) -> int | None:
    """Send a message; returns the message_id (needed for edits)."""
    last_id = None
    for chunk in split_message(text):
        body = {"chat_id": config["chat_id"], "text": chunk}
        if reply_markup is not None and chunk is split_message(text)[-1]:
            body["reply_markup"] = reply_markup
        req = urllib.request.Request(
            f"{API_BASE}{config['bot_token']}/sendMessage",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read())
                last_id = data.get("result", {}).get("message_id", last_id)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:200]
            raise TelegramConfigError(
                f"Telegram API error {exc.code}: {detail}") from exc
    return last_id


def api_call(config: dict, method: str, params: dict, timeout: int = 30) -> dict:
    req = urllib.request.Request(
        f"{API_BASE}{config['bot_token']}/{method}",
        data=json.dumps(params).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:200]
        raise TelegramConfigError(
            f"Telegram API error {exc.code}: {detail}") from exc


def answer_callback(config: dict, callback_query_id: str, text: str) -> None:
    api_call(config, "answerCallbackQuery",
             {"callback_query_id": callback_query_id, "text": text})


def edit_message(config: dict, chat_id, message_id: int, text: str) -> None:
    api_call(config, "editMessageText",
             {"chat_id": chat_id, "message_id": message_id, "text": text})


def get_updates(config: dict, offset: int, timeout: int = 25) -> list:
    """Long-poll for updates (callback buttons); returns the update list."""
    return api_call(config, "getUpdates",
                    {"offset": offset, "timeout": timeout,
                     "allowed_updates": json.dumps(["callback_query"])},
                    timeout=timeout + 10).get("result", [])


def format_briefing(result: dict) -> str:
    """Render the review result as a fixed-template Telegram message (ja).

    Machine records stay English (OSS-facing); the human-facing briefing
    is Japanese. Technical values (paths, binaries, enum values) are kept
    as-is with Japanese glosses.
    """
    session = result.get("request_id", "?")
    a = result.get("assessment", {})

    consistency = a.get("consistency", "?")
    consistency_ja = {
        "aligned": "整合",
        "partial": "部分整合",
        "mismatch": "不整合",
        "insufficient_evidence": "証拠不足",
    }.get(consistency, consistency)

    next_step = a.get("suggested_next_step", "?")
    next_step_ja = {
        "review": "人間レビュー",
        "clarify": "確認要求",
        "escalate": "エスカレーション",
    }.get(next_step, next_step)

    action_prefix_ja = (
        ("read ", "読取 "),
        ("write ", "書込 "),
        ("connect ", "接続 "),
        ("exec ", "実行 "),
        ("open ", "オープン "),
    )

    def action_ja(action: str) -> str:
        if action.startswith("ssh session via warpgate"):
            return "SSHセッション（warpgate経由・記録済み）"
        for prefix, ja in action_prefix_ja:
            if action.startswith(prefix):
                return ja + action[len(prefix):]
        return action

    summary = a.get("summary", "")
    summary_map = {
        "Guardian assessment unavailable; review the evidence and claim manually.":
            "Guardian評価は利用できません — 証拠と申告を手動で確認してください。",
    }
    summary = summary_map.get(summary, summary)

    lines = [
        "agent-zerotrust — セッションレビュー",
        f"セッション: {session}",
        f"ポリシー段階: {result.get('policy_tier', '?')}",
        "",
        "証拠:",
    ]
    for ev in result.get("evidence", []):
        line = f"  [{ev.get('source', '?')}] {action_ja(ev.get('action', '?'))}"
        if ev.get("outcome") == "denied":
            line += "（拒否）"
        lines.append(line)
    lines += ["", f"評価: {consistency}（{consistency_ja}）"]
    lines.append(f"  {summary}")
    flagged = {ev.get("event_id"): ev.get("action")
               for ev in result.get("evidence", [])}
    flags = [flagged.get(eid, eid) for eid in a.get("evidence_ids", [])]
    if flags:
        lines.append("フラグ:")
        for f in dict.fromkeys(flags):  # dedupe, keep order
            lines.append(f"  ! {action_ja(f)}")
    lines.append(f"次の一手: {next_step}（{next_step_ja}）")
    for u in a.get("uncertainties", []):
        lines.append(f"不確実性: {u}")
    lines.append("")
    lines.append("この通知は参考情報です。承認はゲートウェイでのみ行われます。")
    return "\n".join(lines)


def format_request_briefing(result: dict, request: dict) -> str:
    """Render an approval REQUEST briefing (ja) — with the claim clearly
    labeled as untrusted agent-supplied text (T12 briefing discipline)."""
    a = result.get("assessment", {})
    consistency = a.get("consistency", "?")
    consistency_ja = {"aligned": "整合", "partial": "部分整合",
                      "mismatch": "不整合",
                      "insufficient_evidence": "証拠不足"}.get(consistency,
                                                               consistency)
    next_step = a.get("suggested_next_step", "?")
    next_step_ja = {"review": "人間レビュー", "clarify": "確認要求",
                   "escalate": "エスカレーション"}.get(next_step, next_step)

    lines = [
        "agent-zerotrust — 承認リクエスト",
        f"リクエスト: {request.get('request_id', '?')}",
        "",
        "申告（エージェントによる・未検証）:",
        f"  操作: {request.get('action', '?')}",
        f"  理由: {request.get('justification', '?')}",
        "",
        "証拠（直近のセッションコンテキスト）:",
    ]
    for ev in result.get("evidence", [])[:12]:
        lines.append(f"  [{ev.get('source', '?')}] {ev.get('action', '?')}")
    lines += [
        "",
        f"評価: {consistency}（{consistency_ja}）",
        f"  {a.get('summary', '')}",
    ]
    flagged = {ev.get("event_id"): ev.get("action")
               for ev in result.get("evidence", [])}
    flags = [flagged.get(eid, eid) for eid in a.get("evidence_ids", [])]
    if flags:
        lines.append("フラグ:")
        for f in dict.fromkeys(flags):
            lines.append(f"  ! {f}")
    lines.append(f"次の一手: {next_step}（{next_step_ja}）")
    for u in a.get("uncertainties", []):
        lines.append(f"不確実性: {u}")
    lines.append("")
    lines.append("ボタンで承認/拒否を記録できます（アドバイザリ）。"
                 "OS権限の付与はPhase 3で実装されます。")
    return "\n".join(lines)


def request_keyboard(request_id: str) -> dict:
    return {"inline_keyboard": [[
        {"text": "✅ 承認", "callback_data": f"approve:{request_id}"},
        {"text": "🚫 拒否", "callback_data": f"deny:{request_id}"},
    ]]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--send-test", action="store_true")
    group.add_argument("--print-template", action="store_true")
    args = ap.parse_args(argv)

    if args.print_template:
        sample = {
            "request_id": "session-review-sample",
            "policy_tier": "ask",
            "evidence": [{"event_id": "e1", "source": "tetragon",
                          "action": "read /home/ai-muse/canary-secret.txt"}],
            "assessment": {"consistency": "insufficient_evidence",
                           "summary": "1 sensitive file read.",
                           "evidence_ids": ["e1"],
                           "suggested_next_step": "escalate",
                           "uncertainties": ["sample"]},
        }
        print(format_briefing(sample))
        return 0

    try:
        config = load_config()
        send_message(config, "agent-zerotrust: evidence channel is live.")
    except TelegramConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 4
    print("test message sent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
