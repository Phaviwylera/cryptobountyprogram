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
TERMINAL = {"safe", "vulnerable", "low_value", "no_code", "junk", "unverified_final", "error"}


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
                               ("priority", f"REAL NOT NULL DEFAULT {LIVE_PRIORITY}"), ("txs", "INTEGER"),
                               ("payload_confirmed", "INTEGER")):
                if name not in cols:
                    self.db.execute(f"ALTER TABLE contracts ADD COLUMN {name} {decl}")
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_due ON contracts(status, priority DESC, next_try)")
            self.db.commit()
        self.ensure_fund_watch()   # so watch_targets() can always join it, even before the watcher starts

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

    def requeue_status(self, status: str, priority: float) -> int:
        """Send every row with `status` back to the queue (front of it), e.g. to re-judge VULNERABLE
        verdicts after the detection rules change. Returns the number of rows re-queued."""
        with self._lock:
            cur = self.db.execute(
                "UPDATE contracts SET status = 'queued', priority = ?, next_try = 0, attempts = 0, updated = ? "
                "WHERE status = ?", (priority, time.time(), status))
            self.db.commit()
            return cur.rowcount

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

    def claim_one(self, lease: float = 1800.0) -> sqlite3.Row | None:
        """Atomically take the highest-priority due row and LEASE it (push next_try out) so no other
        scan thread grabs it. If the scan finishes, it overwrites the row's status; if it crashes, the
        lease expires and the row becomes due again. Enables safe parallel scanning."""
        with self._lock:
            row = self.db.execute(
                "SELECT * FROM contracts WHERE status IN ('queued','unverified') AND next_try <= ? "
                "ORDER BY priority DESC, next_try, rowid LIMIT 1", (time.time(),)).fetchone()
            if not row:
                return None
            self.db.execute("UPDATE contracts SET next_try = ? WHERE chain = ? AND address = ?",
                            (time.time() + lease, row["chain"], row["address"]))
            self.db.commit()
            return row

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

    # --- Live fund-watch (isolated: its own table, never touches the scan pipeline) -----------------
    def ensure_fund_watch(self) -> None:
        with self._lock:
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS fund_watch (chain TEXT, address TEXT, first_seen REAL, "
                "first_wei TEXT, last_wei TEXT, last_ts REAL, peak_wei TEXT, checks INTEGER, inflows INTEGER, "
                "PRIMARY KEY(chain, address))")
            self.db.commit()

    def recent_vulnerable(self, limit: int = 60) -> list[sqlite3.Row]:
        with self._lock:
            return self.db.execute("SELECT * FROM contracts WHERE status='vulnerable' ORDER BY updated DESC "
                                   "LIMIT ?", (int(limit),)).fetchall()

    def live_vulnerable(self, limit: int = 60) -> list[sqlite3.Row]:
        """Only LIVE-discovered flagged contracts (origin 'block:<n>', seen at the chain head) - fresh
        launches, NOT historical backfill rows (which are old regardless of when we last re-scanned them)."""
        with self._lock:
            return self.db.execute(
                "SELECT * FROM contracts WHERE status='vulnerable' AND origin LIKE 'block:%' "
                "ORDER BY updated DESC LIMIT ?", (int(limit),)).fetchall()

    def watch_targets(self, limit: int = 60) -> list[sqlite3.Row]:
        """Every flagged contract worth watching for incoming funds, REGARDLESS of how it was found:
          * live-discovered fresh launches (origin 'block:*'),
          * payload-CONFIRMED exploits (a real drain proven on a fork) - the ones that most deserve a
            live watch even if they came from backfill or a bounty scope,
          * value-holders (already hold USD), and
          * anything already seen receiving funds (fund_watch inflows>0).
        Deliberately EXCLUDES idle old backfill rows (not live, not confirmed, no value, never received),
        so a year-old re-scanned contract never floods the watch/Live page. Ordered value first."""
        with self._lock:
            return self.db.execute(
                "SELECT * FROM contracts WHERE status='vulnerable' AND ("
                "    origin LIKE 'block:%' OR payload_confirmed = 1 "
                "    OR (value_usd IS NOT NULL AND value_usd > 0) "
                "    OR address IN (SELECT address FROM fund_watch WHERE inflows > 0)"
                ") ORDER BY (value_usd IS NULL), value_usd DESC, updated DESC LIMIT ?", (int(limit),)).fetchall()

    def fund_watch_update(self, chain: str, address: str, wei: int) -> None:
        import time as _t
        now = _t.time()
        with self._lock:
            row = self.db.execute("SELECT last_wei, peak_wei, inflows FROM fund_watch WHERE chain=? AND address=?",
                                  (chain, address)).fetchone()
            if row is None:
                self.db.execute("INSERT INTO fund_watch VALUES (?,?,?,?,?,?,?,?,?)",
                                (chain, address, now, str(wei), str(wei), now, str(wei), 1, 0))
            else:
                last = int(row["last_wei"] or 0)
                inflows = (row["inflows"] or 0) + (1 if wei > last else 0)
                peak = max(int(row["peak_wei"] or 0), wei)
                self.db.execute("UPDATE fund_watch SET last_wei=?, last_ts=?, peak_wei=?, checks=checks+1, "
                                "inflows=? WHERE chain=? AND address=?",
                                (str(wei), now, str(peak), inflows, chain, address))
            self.db.commit()

    def fund_watch_map(self) -> dict:
        with self._lock:
            try:
                return {(r["chain"], r["address"]): r for r in self.db.execute("SELECT * FROM fund_watch").fetchall()}
            except sqlite3.OperationalError:
                return {}

    def cursor(self, chain: str) -> int | None:
        with self._lock:
            row = self.db.execute("SELECT block FROM cursors WHERE chain = ?", (chain,)).fetchone()
            return row[0] if row else None

    def set_cursor(self, chain: str, block: int) -> None:
        with self._lock:
            self.db.execute("INSERT INTO cursors (chain, block) VALUES (?, ?) ON CONFLICT(chain) DO UPDATE SET block = excluded.block", (chain, block))
            self.db.commit()
