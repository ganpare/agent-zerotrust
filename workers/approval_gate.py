"""Approval gate for classified worker delegations.

When Jev classifies a request as secrets / monitoring / destructive, the
worker does not run. Instead the owner gets a Telegram message with
[承認] / [拒否] buttons and the delegation waits for the answer.

The wait is bounded: no answer within the TTL means denied (fail closed).
Decisions are recorded through the existing approval store, so the audit
trail is the same as for privileged operations.
"""
from __future__ import annotations

import time
import uuid

from approvals import store
from evidence.telegram import (TelegramConfigError, answer_callback,
                               edit_message, get_updates, load_config,
                               request_keyboard, send_message)

DEFAULT_TTL_SECONDS = 600  # 10 minutes


def request_worker_approval(
    instruction: str,
    category_label: str,
    confidence: float,
    agent: str,
    target: str,
    source_label: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> dict:
    """Ask the owner to approve a risky delegation; block until answered.

    Returns {"approved": bool, "request_id": str, "reason": str}.
    """
    request_id = f"WREQ-{int(time.time())}-{uuid.uuid4().hex[:6]}"
    action = f"[{category_label}] {agent} → {target}"
    justification = instruction[:1500]

    store.create_request(request_id, action, justification, "worker-gateway")

    try:
        config = load_config()
    except TelegramConfigError as exc:
        return {"approved": False, "request_id": request_id,
                "reason": f"Telegram 未設定のため承認できません: {exc}"}

    text = (
        "⚠️ agent-zerotrust — ワーカー依頼の承認が必要です\n"
        f"依頼元: {source_label}\n"
        f"分類: {category_label}（信頼度 {confidence:.2f}）\n"
        f"エージェント: {agent} (対象: {target})\n"
        f"リクエスト: {request_id}\n"
        "\n依頼内容:\n"
        f"{instruction}\n"
        "\n"
        f"{ttl_seconds // 60} 分以内に回答がなければ拒否として扱います。"
    )
    try:
        send_message(config, text, reply_markup=request_keyboard(request_id))
    except TelegramConfigError as exc:
        return {"approved": False, "request_id": request_id,
                "reason": f"Telegram 送信に失敗しました: {exc}"}

    deadline = time.time() + ttl_seconds
    offset = None
    while time.time() < deadline:
        try:
            updates = get_updates(config, offset if offset is not None else -1,
                                  timeout=10)
        except (TelegramConfigError, Exception):
            time.sleep(2)
            continue
        for upd in updates:
            offset = max(offset or 0, upd["update_id"] + 1)
            cb = upd.get("callback_query")
            if not cb:
                continue
            data = cb.get("data", "")
            if ":" not in data:
                continue
            decision, rid = data.split(":", 1)
            if rid != request_id or decision not in ("approve", "deny"):
                continue

            approved = decision == "approve"
            store.add_decision(request_id, "approved" if approved else "denied",
                               "telegram:human")
            message = cb.get("message") or {}
            try:
                answer_callback(config, cb["id"],
                                "✅ 承認しました" if approved else "🚫 拒否しました")
                if message.get("chat") and message.get("message_id"):
                    edit_message(config, message["chat"]["id"],
                                 message["message_id"],
                                 ("✅ 承認しました\n" if approved
                                  else "🚫 拒否しました\n") + f"リクエスト: {request_id}")
            except TelegramConfigError:
                pass
            return {"approved": approved, "request_id": request_id,
                    "reason": "承認されました" if approved else "拒否されました"}

    return {"approved": False, "request_id": request_id,
            "reason": f"{ttl_seconds // 60} 分以内に回答がなかったため拒否しました"}
