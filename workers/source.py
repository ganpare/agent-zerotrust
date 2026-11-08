"""Resolve a connection's source IP to a Tailscale node identity.

The MCP server binds the tailnet address, so every request arrives from a
Tailscale peer. `tailscale status --json` maps each peer's IP to its
hostname, OS, and tags, which lets the owner see *who* delegated a task.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time

_CACHE_TTL = 60.0
_cache: dict = {"at": 0.0, "by_ip": {}}


def _load_peers() -> dict[str, dict]:
    """Return {ip: {name, os, tags, online}} from tailscale status."""
    now = time.time()
    if now - _cache["at"] < _CACHE_TTL and _cache["by_ip"]:
        return _cache["by_ip"]

    exe = shutil.which("tailscale") or "/usr/bin/tailscale"
    try:
        out = subprocess.run([exe, "status", "--json"], capture_output=True,
                             text=True, timeout=10)
        data = json.loads(out.stdout or "{}")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return _cache["by_ip"]

    by_ip: dict[str, dict] = {}
    for peer in (data.get("Peer") or {}).values():
        info = {
            "name": peer.get("HostName") or peer.get("DNSName", "").split(".")[0],
            "os": peer.get("OS", ""),
            "tags": peer.get("Tags") or [],
            "online": bool(peer.get("Online")),
        }
        for ip in peer.get("TailscaleIPs") or []:
            by_ip[ip] = info
    # the local node, so a request from the host itself is labelled too
    self_info = data.get("Self") or {}
    for ip in self_info.get("TailscaleIPs") or []:
        by_ip[ip] = {
            "name": self_info.get("HostName", "self"),
            "os": self_info.get("OS", ""),
            "tags": self_info.get("Tags") or [],
            "online": True,
        }
    _cache["at"] = now
    _cache["by_ip"] = by_ip
    return by_ip


def describe_source(ip: str | None) -> str:
    """Human-readable label for a request's origin (Japanese)."""
    if not ip:
        return "不明"
    if ip.startswith("127.") or ip in ("::1", "localhost"):
        return "ローカル（このホスト）"
    info = _load_peers().get(ip)
    if not info:
        return f"{ip}（Tailscale未登録）"
    parts = [info["name"]]
    if info.get("os"):
        parts.append(info["os"])
    tags = [t for t in info.get("tags", []) if isinstance(t, str)]
    if tags:
        parts.append(" ".join(tags))
    return f"{' / '.join(parts)} ({ip})"
