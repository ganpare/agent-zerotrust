"""Append-only redemption ledger with atomic use consumption.

SQLite is the ledger: writers serialize, so the UPDATE-based slot
acquisition is atomic — a concurrent double-redeem fails exactly one.
Every redemption and every denial is recorded as evidence.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time


class Ledger:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        self._init()

    def _init(self) -> None:
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS leases (
                    lease_id   TEXT PRIMARY KEY,
                    uses       INTEGER NOT NULL DEFAULT 0,
                    first_use  REAL,
                    last_use   REAL
                )""")
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS uses (
                    lease_id   TEXT NOT NULL,
                    use_no     INTEGER NOT NULL,
                    command    TEXT,
                    returncode INTEGER,
                    stdout     TEXT,
                    stderr     TEXT,
                    at         REAL,
                    PRIMARY KEY (lease_id, use_no)
                )""")
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS denials (
                    denial_id  TEXT PRIMARY KEY,
                    principal  TEXT,
                    op_class   TEXT,
                    args       TEXT,
                    reason     TEXT,
                    detail     TEXT,
                    at         REAL
                )""")

    def consume_use(self, lease_id: str, max_uses: int) -> int | None:
        """Atomically acquire one use slot. Returns the 1-based use number,
        or None when the lease has no uses left (or the max is invalid)."""
        if not isinstance(max_uses, int) or max_uses < 1:
            return None
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO leases (lease_id, uses, first_use) "
                "VALUES (?, 0, ?)", (lease_id, time.time()))
            cur = self.conn.execute(
                "UPDATE leases SET uses = uses + 1, last_use = ? "
                "WHERE lease_id = ? AND uses < ?",
                (time.time(), lease_id, max_uses))
            if cur.rowcount != 1:
                return None
            row = self.conn.execute(
                "SELECT uses FROM leases WHERE lease_id = ?",
                (lease_id,)).fetchone()
            return int(row[0])

    def record_use(self, lease_id: str, use_no: int, command: list[str],
                   returncode: int, stdout: str, stderr: str) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO uses (lease_id, use_no, command, "
                "returncode, stdout, stderr, at) VALUES (?,?,?,?,?,?,?)",
                (lease_id, use_no, " ".join(command), returncode,
                 stdout[:4000], stderr[:4000], time.time()))

    def record_denial(self, denial_id: str, principal: str, op_class: str,
                      args: dict, reason: str, detail: str = "") -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO denials (denial_id, principal, "
                "op_class, args, reason, detail, at) VALUES (?,?,?,?,?,?,?)",
                (denial_id, principal, op_class, json.dumps(args), reason,
                 detail, time.time()))

    def uses(self, lease_id: str) -> int:
        row = self.conn.execute(
            "SELECT uses FROM leases WHERE lease_id = ?",
            (lease_id,)).fetchone()
        return int(row[0]) if row else 0

