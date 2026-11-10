"""Persistent scan queue (SQLite): every contract is scanned once, runs resume where they stopped."""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS contracts (
    chain        TEXT NOT NULL,
    address      TEXT NOT NULL,
    origin       TEXT,
    status       TEXT NOT NULL DEFAULT 'queued',
    attempts     INTEGER NOT NULL DEFAULT 0,
    next_try     REAL NOT NULL DEFAULT 0,
    name         TEXT,
    max_severity TEXT,
    findings     INTEGER,
    balance_wei  TEXT,
    report       TEXT,
    error        TEXT,
    updated      REAL,
    PRIMARY KEY (chain, address)
);
CREATE TABLE IF NOT EXISTS cursors (chain TEXT PRIMARY KEY, block INTEGER NOT NULL);
"""

# queued -> safe | vulnerable | unverified (retried) | low_value | no_code | error
TERMINAL = {"safe", "vulnerable", "low_value", "no_code", "unverified_final", "error"}


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False + an explicit lock: the web worker thread and request
        # threads share one connection safely (every access goes through self._lock).
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.RLock()
        with self._lock:
            self.db.executescript(SCHEMA)

    def enqueue(self, chain: str, address: str, origin: str) -> bool:
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO contracts (chain, address, origin, updated) VALUES (?, ?, ?, ?)",
                (chain.lower(), address.lower(), origin, time.time()),
            )
            self.db.commit()
            return cur.rowcount == 1

    def due(self, limit: int | None = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM contracts WHERE status IN ('queued', 'unverified') AND next_try <= ? ORDER BY next_try, rowid"
        with self._lock:
            return self.db.execute(q + (f" LIMIT {int(limit)}" if limit else ""), (time.time(),)).fetchall()

    def pending_count(self) -> int:
        with self._lock:
            return self.db.execute("SELECT COUNT(*) FROM contracts WHERE status IN ('queued','unverified')").fetchone()[0]

    def update(self, chain: str, address: str, **fields) -> None:
        fields["updated"] = time.time()
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self._lock:
            self.db.execute(f"UPDATE contracts SET {cols} WHERE chain = ? AND address = ?", (*fields.values(), chain, address))
            self.db.commit()

    def reset(self, statuses: set[str]) -> int:
        marks = ",".join("?" * len(statuses))
        with self._lock:
            cur = self.db.execute(f"UPDATE contracts SET status='queued', attempts=0, next_try=0 WHERE status IN ({marks})", tuple(statuses))
            self.db.commit()
            return cur.rowcount

    def counts(self) -> dict[str, int]:
        with self._lock:
            return {r[0]: r[1] for r in self.db.execute("SELECT status, COUNT(*) FROM contracts GROUP BY status")}

    def by_status(self, status: str) -> list[sqlite3.Row]:
        with self._lock:
            return self.db.execute("SELECT * FROM contracts WHERE status = ? ORDER BY updated DESC", (status,)).fetchall()

    def fetch_one(self, chain: str, address: str) -> sqlite3.Row | None:
        with self._lock:
            return self.db.execute("SELECT * FROM contracts WHERE chain=? AND address=?", (chain, address)).fetchone()

    def cursor(self, chain: str) -> int | None:
        with self._lock:
            row = self.db.execute("SELECT block FROM cursors WHERE chain = ?", (chain,)).fetchone()
            return row[0] if row else None

    def set_cursor(self, chain: str, block: int) -> None:
        with self._lock:
            self.db.execute("INSERT INTO cursors (chain, block) VALUES (?, ?) ON CONFLICT(chain) DO UPDATE SET block = excluded.block", (chain, block))
            self.db.commit()
