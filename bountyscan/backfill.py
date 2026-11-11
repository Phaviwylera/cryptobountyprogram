"""Historical backfill: scan contracts verified over the past N days, not only new deployments.

Brute-forcing every block is not viable (6 months of Ethereum is ~1.3M blocks, ~730 GB through a
public RPC), and only *verified* contracts can be scanned anyway. So the backfill walks Blockscout's
list of verified contracts newest-to-oldest and, per page of 50:

  1. drops dead ones - no transactions, no balance, no market cap (dead clones, test deploys, scams);
  2. drops wallet proxies (Gnosis Safe user wallets: their logic is the audited Safe singleton);
  3. prices the survivors in one Multicall3 eth_call (native + major tokens, USD);
  4. queues them with priority = value held, so funded contracts are scanned first.

Progress (cursor, counters, date reached) is persisted, so it resumes after restarts.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

from .rpc import RPC
from .sources import blockscout_verified_page, chain_id_of
from .value import holdings_many

# Gnosis Safe user wallets: thousands of identical proxies whose logic is the audited Safe singleton.
WALLET_PROXIES = {"SafeProxy", "GnosisSafeProxy"}


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def alive(item: dict, min_txs: int) -> bool:
    txs = int(item.get("transactions_count") or 0)
    bal = int(item.get("coin_balance") or 0)
    try:
        mcap = float(item.get("market_cap") or 0)
    except (TypeError, ValueError):
        mcap = 0.0
    return txs >= min_txs or bal > 0 or mcap > 0


class Backfill:
    def __init__(self, store, rpc: RPC | None, on_event=None, on_queue=None):
        self.store = store
        self.rpc = rpc
        self.on_event = on_event or (lambda kind, msg: None)
        self.on_queue = on_queue or (lambda: None)   # tell the scan worker there is work
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.state = store.get_meta("backfill", None) or {}
        self.last_error: str | None = None

    # ---------------------------------------------------------------- control
    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self, chain: str = "ethereum", days: int = 180, min_txs: int = 10) -> None:
        chain = chain.lower()
        st = self.state
        same = st.get("chain") == chain and st.get("days") == days and st.get("min_txs") == min_txs
        if not same or st.get("done"):
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            self.state = {"chain": chain, "days": days, "min_txs": min_txs, "cutoff": cutoff.isoformat(),
                          "cursor": None, "listed": 0, "alive": 0, "queued": 0, "skipped_wallets": 0,
                          "value_queued_usd": 0.0, "reached": None, "started": time.time(), "done": False}
        self.state["paused"] = False
        self._save()
        self._stop.clear()
        if not self.running:
            self._thread = threading.Thread(target=self._run, daemon=True, name="bountyscan-backfill")
            self._thread.start()
        self.on_event("info", f"Backfill started: verified contracts on {chain} from the last {days} days "
                              f"(alive = >= {min_txs} txs, a balance, or a market cap), richest first.")

    def stop(self) -> None:
        self._stop.set()
        self.state["paused"] = True
        self._save()

    def _save(self) -> None:
        self.store.set_meta("backfill", self.state)

    # ---------------------------------------------------------------- progress
    def snapshot(self) -> dict:
        st = dict(self.state)
        if not st:
            return {"active": False}
        cutoff, reached = _parse_ts(st.get("cutoff")), _parse_ts(st.get("reached"))
        pct = 0.0
        if cutoff and reached:
            total = (datetime.now(timezone.utc) - cutoff).total_seconds()
            pct = max(0.0, min(100.0, 100 * (datetime.now(timezone.utc) - reached).total_seconds() / total))
        if st.get("done"):
            pct = 100.0
        st.update(active=True, running=self.running, percent=round(pct, 1), last_error=self.last_error)
        return st

    # ---------------------------------------------------------------- loop
    def _run(self) -> None:
        st = self.state
        chain, min_txs = st["chain"], st["min_txs"]
        cutoff = _parse_ts(st["cutoff"])
        cid = chain_id_of(chain)
        while not self._stop.is_set():
            try:
                items, nxt = blockscout_verified_page(chain, st.get("cursor"))
            except Exception as exc:   # network blip / rate limit: back off, keep the cursor
                self.last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(15)
                continue
            self.last_error = None
            if not items:
                st["done"] = True
                break
            cands, finished = [], False
            for it in items:
                ts = _parse_ts(it.get("verified_at"))
                if ts and cutoff and ts < cutoff:
                    finished = True
                    break
                st["listed"] += 1
                st["reached"] = it.get("verified_at") or st.get("reached")
                if (it.get("language") or "solidity").lower() != "solidity" or not alive(it, min_txs):
                    continue
                name = (it.get("address") or {}).get("name") or ""
                if name in WALLET_PROXIES:
                    st["skipped_wallets"] += 1
                    continue
                cands.append((it["address"]["hash"], name, int(it.get("transactions_count") or 0)))
            st["alive"] += len(cands)

            values = {}
            if cands and self.rpc is not None:
                try:
                    values = holdings_many(self.rpc, cid, [a for a, _, _ in cands])
                except Exception as exc:
                    self.last_error = f"value check: {exc}"
            added = 0
            for addr, name, txs in cands:
                h = values.get(addr.lower())
                usd = h["usd"] if h else None
                fields = {"name": name or None, "txs": txs,
                          "priority": (usd or 0) + min(txs, 10**6) * 0.01}
                if h:
                    import json
                    fields.update(value_usd=usd, holdings=json.dumps(h["items"]), value_checked=time.time())
                if self.store.enqueue_with(chain, addr, "backfill:blockscout", **fields):
                    added += 1
                    st["value_queued_usd"] = round(st.get("value_queued_usd", 0) + (usd or 0), 2)
                    if usd and usd >= 100_000:
                        self.on_event("found", f"Backfill queued {addr} ({name or 'unnamed'}) holding ${usd:,.0f} - scanning it first.")
            st["queued"] += added
            if added:
                self.on_queue()
            st["cursor"] = nxt
            self._save()
            if finished or nxt is None:
                st["done"] = True
                break
        if st.get("done"):
            self._save()
            self.on_event("info", f"Backfill listing complete: {st['listed']:,} verified contracts listed, "
                                  f"{st['alive']:,} alive, {st['queued']:,} queued for scanning.")
