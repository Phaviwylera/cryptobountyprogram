"""Live fund-watch for the Live Scan page.

Completely isolated from the scan pipeline: a single daemon thread periodically reads the NATIVE balance
of the freshest flagged (vulnerable) contracts and records the trend in its own `fund_watch` table. The
point is to surface a brand-new vulnerable contract that starts RECEIVING funds - a live, winnable target -
without touching how scanning/verification works. If anything here fails it is swallowed; the main
pipeline is never affected.
"""
from __future__ import annotations

import json
import threading
import urllib.request


def rpc_balance_wei(rpc_url: str, address: str) -> int | None:
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                           "params": [address, "latest"]}).encode()
        req = urllib.request.Request(rpc_url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return int((json.loads(r.read().decode()).get("result") or "0x0"), 16)
    except Exception:
        return None


class FundWatcher(threading.Thread):
    """Polls native balances of the freshest flagged contracts and records inflow trend."""

    def __init__(self, store, rpc_url: str | None, interval: int = 90, top: int = 50, chain: str = "ethereum"):
        super().__init__(daemon=True, name="fund-watch")
        self.store = store
        self.rpc_url = rpc_url
        self.interval = interval
        self.top = top
        self.chain = chain
        self._stop = threading.Event()
        try:
            store.ensure_fund_watch()
        except Exception:
            pass

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        if not self.rpc_url:
            return
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def _tick(self) -> None:
        for r in self.store.live_vulnerable(self.top):   # watch only fresh, live-discovered contracts
            if self._stop.is_set():
                return
            if r["chain"] != self.chain:        # native-balance watch is single-chain for now
                continue
            wei = rpc_balance_wei(self.rpc_url, r["address"])
            if wei is not None:
                self.store.fund_watch_update(r["chain"], r["address"], wei)
