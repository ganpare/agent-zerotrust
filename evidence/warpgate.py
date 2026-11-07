"""Minimal Warpgate admin API client (stdlib only).

The warpgate TLS certificate is self-signed by default, so verification is
disabled explicitly — the client talks to a known host over Tailscale.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request


class WarpgateError(RuntimeError):
    pass


class WarpgateClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self._creds = {"username": username, "password": password}
        self._cookie: str | None = None
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self._cookie:
            req.add_header("Cookie", self._cookie)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=20) as resp:
                set_cookie = resp.headers.get("Set-Cookie")
                if set_cookie:
                    self._cookie = set_cookie.split(";")[0]
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raise WarpgateError(f"{method} {path}: HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise WarpgateError(f"{method} {path}: {exc.reason}") from exc

    def login(self) -> "WarpgateClient":
        self._request("POST", "/@warpgate/api/auth/login", self._creds)
        return self

    def sessions(self) -> list[dict]:
        data = self._request("GET", "/@warpgate/admin/api/sessions")
        return data.get("items", []) if isinstance(data, dict) else data

    def session(self, session_id: str) -> dict | None:
        for s in self.sessions():
            if s.get("id") == session_id:
                return s
        return None
