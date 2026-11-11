"""What a contract actually holds, in USD: native coin + the major tokens DeFi value sits in.

Native balance alone is misleading - a vault holding $5M of USDC has 0 ETH. Prices come from
Chainlink feeds read on-chain (no third-party API, no key). Read-only eth_calls only.
Token addresses, decimals and feeds were verified on-chain when this table was written.
"""
from __future__ import annotations

import time

from .rpc import RPC, RPCError

BALANCE_OF = "0x70a08231"
LATEST_ROUND = "0xfeaf968c"
DECIMALS = "0x313ce567"
STETH_PER_TOKEN = "0x035faf82"

# chain id -> [(symbol, address, decimals, price kind)]
TOKENS: dict[int, list[tuple[str, str, int, str]]] = {
    1: [
        ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6, "usd"),
        ("USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7", 6, "usd"),
        ("DAI", "0x6B175474E89094C44Da98b954EedeAC495271d0F", 18, "usd"),
        ("USDS", "0xdC035D45d973E3EC169d2276DDab16f1e407384F", 18, "usd"),
        ("USDe", "0x4c9EDD5852cd905f086C759E8383e09bff1E68B3", 18, "usd"),
        ("WETH", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 18, "eth"),
        ("stETH", "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", 18, "eth"),
        ("wstETH", "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0", 18, "wsteth"),
        ("WBTC", "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", 8, "btc"),
    ],
}
# chain id -> Chainlink feeds on that chain
FEEDS: dict[int, dict[str, str]] = {
    1: {"eth": "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419", "btc": "0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c"},
}
NATIVE_KIND = {1: "eth"}     # what the chain's native coin is priced as
PRICE_TTL = 600              # seconds

_price_cache: dict[int, tuple[float, dict[str, float]]] = {}


def _call(rpc: RPC, to: str, data: str) -> str:
    return rpc.call("eth_call", [{"to": to, "data": data}, "latest"]) or "0x"


def prices(rpc: RPC, chain_id: int) -> dict[str, float]:
    """USD prices for this chain's price kinds, cached for 10 minutes. Missing feeds are omitted."""
    hit = _price_cache.get(chain_id)
    if hit and time.time() - hit[0] < PRICE_TTL:
        return hit[1]
    out = {"usd": 1.0}
    for kind, feed in FEEDS.get(chain_id, {}).items():
        try:
            h = _call(rpc, feed, LATEST_ROUND)[2:]
            answer, updated = int(h[64:128], 16), int(h[192:256], 16)
            dec = int(_call(rpc, feed, DECIMALS), 16)
            if answer > 0 and time.time() - updated < 6 * 3600:   # ignore stale/broken feeds
                out[kind] = answer / 10**dec
        except (RPCError, ValueError):
            continue
    if "eth" in out:
        try:
            ratio = int(_call(rpc, "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0", STETH_PER_TOKEN), 16) / 1e18
            if 1.0 <= ratio <= 2.0:
                out["wsteth"] = out["eth"] * ratio
        except (RPCError, ValueError):
            pass
    _price_cache[chain_id] = (time.time(), out)
    return out


def holdings(rpc: RPC, chain_id: int, address: str, native_wei: int | None) -> dict:
    """{'usd': total or None, 'items': [{symbol, amount, usd}], 'priced': bool}"""
    px = prices(rpc, chain_id)
    items, total, priced = [], 0.0, False
    if native_wei:
        amount = native_wei / 1e18
        kind = NATIVE_KIND.get(chain_id)
        usd = amount * px[kind] if kind in px else None
        items.append({"symbol": "native", "amount": amount, "usd": usd})
        if usd is not None:
            total += usd
            priced = True
    padded = "0" * 24 + address.lower()[2:]
    for sym, tok, dec, kind in TOKENS.get(chain_id, []):
        try:
            raw = int(_call(rpc, tok, BALANCE_OF + padded), 16)
        except (RPCError, ValueError):
            continue
        if not raw:
            continue
        amount = raw / 10**dec
        usd = amount * px[kind] if kind in px else None
        items.append({"symbol": sym, "amount": amount, "usd": usd})
        if usd is not None:
            total += usd
            priced = True
    items.sort(key=lambda i: -(i["usd"] or 0))
    has_table = chain_id in TOKENS or chain_id in NATIVE_KIND
    return {"usd": round(total, 2) if (priced or has_table) else None, "items": items, "priced": priced}


def describe(h: dict | None) -> str:
    if not h:
        return "unknown"
    def amt(x: float) -> str:
        return f"{x:,.2f}" if x >= 1 else f"{x:.4g}"
    parts = [f"{amt(i['amount'])} {i['symbol']}" + (f" (${i['usd']:,.0f})" if i["usd"] is not None else "")
             for i in h.get("items", [])]
    head = f"${h['usd']:,.2f}" if h.get("usd") is not None else "unpriced"
    return head + (" - " + ", ".join(parts) if parts else " - holds nothing")
