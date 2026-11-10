"""Minimal Ethereum JSON-RPC client (stdlib only) for discovery and balance checks. Read-only."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request


class RPCError(RuntimeError):
    pass


class RPC:
    def __init__(self, url: str, min_interval: float = 0.05, retries: int = 4):
        self.url = url
        self.min_interval = min_interval
        self.retries = retries
        self._last = 0.0
        self._id = 0

    def call(self, method: str, params: list):
        payload = None
        for attempt in range(self.retries):
            wait = self.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._id += 1
            body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
            req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json", "User-Agent": "bountyscan/0.2"})
            try:
                self._last = time.monotonic()
                with urllib.request.urlopen(req, timeout=30) as resp:
                    payload = json.loads(resp.read().decode())
                if "error" in payload:
                    raise RPCError(f"{method}: {payload['error']}")
                return payload.get("result")
            except (urllib.error.URLError, TimeoutError, RPCError, json.JSONDecodeError) as exc:
                if attempt == self.retries - 1:
                    raise RPCError(f"{method} failed after {self.retries} attempts: {exc}") from exc
                time.sleep(1.5 * (attempt + 1))
        raise RPCError(f"{method}: no response")

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)

    def block(self, number: int, full: bool = True) -> dict:
        return self.call("eth_getBlockByNumber", [hex(number), full]) or {}

    def receipt(self, tx_hash: str) -> dict:
        return self.call("eth_getTransactionReceipt", [tx_hash]) or {}

    def balance(self, address: str) -> int:
        return int(self.call("eth_getBalance", [address, "latest"]), 16)

    def code(self, address: str) -> str:
        return self.call("eth_getCode", [address, "latest"]) or "0x"

    def created_contracts(self, number: int) -> list[str]:
        """Contracts deployed directly by transactions in a block (factory-internal creations are not visible here)."""
        out = []
        for tx in self.block(number, True).get("transactions", []):
            if isinstance(tx, dict) and tx.get("to") is None:
                addr = self.receipt(tx["hash"]).get("contractAddress")
                if addr:
                    out.append(addr)
        return out
