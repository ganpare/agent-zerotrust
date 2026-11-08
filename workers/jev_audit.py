"""Jev-based audit — fast, typed classification of a delegation request.

Instead of an LLM, this uses TypeSafe's System One model (Jev), which answers
a typed Choice question in milliseconds and returns probabilities and
confidence. No text generation, so no ideological drift and no NSFW
false-positives beyond the category we define ourselves.

Five categories:
  normal      ordinary engineering work          -> allow
  nsfw        adult content                      -> allow
  secrets     requests for keys/tokens/.env      -> ask the human
  monitoring  stops or tampers with monitoring   -> ask the human
  destructive destructive operations             -> ask the human

The API key is read from Infisical at startup and cached in memory.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

TYPESAFE_URL = "https://api.typesafe.ai/v1/systemone"
JEV_MODEL = os.environ.get("TYPESAFE_MODEL", "jev-1.13.0")

INFISICAL_URL = os.environ.get("INFISICAL_URL", "http://127.0.0.1:8088")
INFISICAL_PROJECT = os.environ.get("INFISICAL_PROJECT", "zero-trust")
INFISICAL_ENV = os.environ.get("INFISICAL_ENV", "dev")
INFISICAL_SECRET = "TYPESAFE_API_KEY"
CRED_DIR = Path(os.environ.get(
    "INFISICAL_CRED_DIR", str(Path.home() / ".config/infisical")))

CATEGORIES: dict[str, str] = {
    "normal": "通常の作業。コード編集、テスト実行、調査、ビルド、ファイル操作など",
    "nsfw": "性的な内容、アダルトコンテンツ、エロティックな文章",
    "secrets": "秘密鍵、SSH鍵、APIトークン、パスワード、.env などの認証情報の取得や表示",
    "monitoring": "監視・セキュリティソフトウェアの停止、無効化、設定の改ざん",
    "destructive": "データの破壊的削除、フォーマット、重要なサービスの停止",
}

# categories that need the owner's explicit approval before running
NEEDS_APPROVAL = {"secrets", "monitoring", "destructive"}

_key_cache: dict = {"value": None, "at": 0.0}
_KEY_TTL = 3600.0


class AuditError(RuntimeError):
    pass


def _infisical_token() -> str:
    cid = (CRED_DIR / "client-id").read_text().strip()
    secret = (CRED_DIR / "client-secret").read_text().strip()
    body = json.dumps({"clientId": cid, "clientSecret": secret}).encode()
    req = urllib.request.Request(
        f"{INFISICAL_URL}/api/v1/auth/universal-auth/login",
        data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:
        token = json.loads(resp.read()).get("accessToken")
    if not token:
        raise AuditError("Infisical login returned no token")
    return token


def get_api_key() -> str:
    """Fetch the TypeSafe key from Infisical, cached for an hour."""
    env_key = os.environ.get("TYPESAFE_API_KEY")
    if env_key:
        return env_key
    now = time.time()
    if _key_cache["value"] and now - _key_cache["at"] < _KEY_TTL:
        return _key_cache["value"]

    token = _infisical_token()
    url = (f"{INFISICAL_URL}/api/v3/secrets/raw/{INFISICAL_SECRET}"
           f"?workspaceSlug={INFISICAL_PROJECT}&environment={INFISICAL_ENV}")
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
    key = (data.get("secret") or {}).get("secretValue")
    if not key:
        raise AuditError("TYPESAFE_API_KEY not found in Infisical")
    _key_cache.update(value=key, at=now)
    return key


def classify(text: str, timeout: int = 15) -> dict:
    """Classify text into one of the five categories via Jev.

    Returns {"category", "confidence", "probabilities", "elapsed_ms",
             "needs_approval", "error"}.
    """
    started = time.time()
    try:
        key = get_api_key()
    except (AuditError, OSError, urllib.error.URLError) as exc:
        return {
            "category": "normal", "confidence": 0.0, "probabilities": {},
            "elapsed_ms": int((time.time() - started) * 1000),
            "needs_approval": False,
            "error": f"APIキーを取得できませんでした: {type(exc).__name__}",
        }

    body = json.dumps({
        "model": JEV_MODEL,
        "state": text[:8000],
        "questions": {
            "category": {
                "type": "choice",
                "instructions": "この依頼は何を求めているか",
                "criteria": CATEGORIES,
            }
        },
    }).encode()
    req = urllib.request.Request(
        TYPESAFE_URL, data=body, method="POST",
        headers={"Authorization": f"Bearer {key}",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        return {
            "category": "normal", "confidence": 0.0, "probabilities": {},
            "elapsed_ms": int((time.time() - started) * 1000),
            "needs_approval": False,
            "error": f"Jev の呼び出しに失敗しました: {type(exc).__name__}",
        }

    answer = (data.get("answers") or {}).get("category") or {}
    category = answer.get("choice") or "normal"
    return {
        "category": category,
        "confidence": answer.get("confidence", 0.0),
        "probabilities": answer.get("probabilities", {}),
        "elapsed_ms": int((time.time() - started) * 1000),
        "needs_approval": category in NEEDS_APPROVAL,
        "error": None,
    }


CATEGORY_JA = {
    "normal": "通常の作業",
    "nsfw": "NSFW系",
    "secrets": "秘密鍵・認証情報",
    "monitoring": "監視の停止・改ざん",
    "destructive": "破壊的な操作",
}


def label(category: str) -> str:
    return CATEGORY_JA.get(category, category)
