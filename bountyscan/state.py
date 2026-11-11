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
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scan_cache (source_hash TEXT PRIMARY KEY, status TEXT NOT NULL, ref_address TEXT, at REAL);
"""
LIVE_PRIORITY = 1e9   # live/Immunefi items jump the queue; backfill items are ordered by value

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
            # additive migrations for databases created by older versions
            cols = {r[1] for r in self.db.execute("PRAGMA table_info(contracts)")}
            for name, decl in (("value_usd", "REAL"), ("holdings", "TEXT"), ("value_checked", "REAL"),
                               ("priority", f"REAL NOT NULL DEFAULT {LIVE_PRIORITY}"), ("txs", "INTEGER")):
                if name not in cols:
                    self.db.execute(f"ALTER TABLE contracts ADD COLUMN {name} {decl}")
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_due ON contracts(status, priority DESC, next_try)")
            self.db.commit()

    # ---- queue with priority (backfill) -------------------------------------------------
    def enqueue_with(self, chain: str, address: str, origin: str, **fields) -> bool:
        """Insert if new and set extra columns (priority, value_usd, name, txs ...). Existing rows untouched."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO contracts (chain, address, origin, updated) VALUES (?, ?, ?, ?)",
                (chain.lower(), address.lower(), origin, time.time()))
            if cur.rowcount == 1 and fields:
                cols = ", ".join(f"{k} = ?" for k in fields)
                self.db.execute(f"UPDATE contracts SET {cols} WHERE chain = ? AND address = ?",
                                (*fields.values(), chain.lower(), address.lower()))
            self.db.commit()
            return cur.rowcount == 1

    # ---- small key/value store (backfill progress) ---------------------------------------
    def get_meta(self, key: str, default=None):
        import json
        with self._lock:
            row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_meta(self, key: str, value) -> None:
        import json
        with self._lock:
            self.db.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                            (key, json.dumps(value)))
            self.db.commit()

    # ---- identical-source scan cache ------------------------------------------------------
    def cached_verdict(self, source_hash: str):
        with self._lock:
            return self.db.execute("SELECT status, ref_address FROM scan_cache WHERE source_hash = ?", (source_hash,)).fetchone()

    def cache_verdict(self, source_hash: str, status: str, ref_address: str) -> None:
        with self._lock:
            self.db.execute("INSERT OR IGNORE INTO scan_cache (source_hash, status, ref_address, at) VALUES (?, ?, ?, ?)",
                            (source_hash, status, ref_address, time.time()))
            self.db.commit()

    def enqueue(self, chain: str, address: str, origin: str) -> bool:
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO contracts (chain, address, origin, updated) VALUES (?, ?, ?, ?)",
                (chain.lower(), address.lower(), origin, time.time()),
            )
            self.db.commit()
            return cur.rowcount == 1

    def due(self, limit: int | None = None) -> list[sqlite3.Row]:
        q = ("SELECT * FROM contracts WHERE status IN ('queued', 'unverified') AND next_try <= ? "
             "ORDER BY priority DESC, next_try, rowid")
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

    def value_stats(self) -> dict:
        """USD held by scanned contracts, and by the vulnerable ones (only rows with a known value)."""
        with self._lock:
            seen, priced = self.db.execute(
                "SELECT COALESCE(SUM(value_usd),0), COUNT(value_usd) FROM contracts WHERE status IN ('safe','vulnerable')").fetchone()
            vuln = self.db.execute("SELECT COALESCE(SUM(value_usd),0) FROM contracts WHERE status='vulnerable'").fetchone()[0]
            top = self.db.execute("SELECT COALESCE(MAX(value_usd),0) FROM contracts WHERE status IN ('safe','vulnerable')").fetchone()[0]
        return {"seen_usd": seen, "priced": priced, "vulnerable_usd": vuln, "max_usd": top}

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
