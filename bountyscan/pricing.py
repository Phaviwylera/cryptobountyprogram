"""Exotic-token pricing for the TVL floor.

The floor in value.py prices native + 6 major tokens via on-chain Chainlink feeds (no external dep). That
undercounts a pool whose value sits in a mid-cap token (LINK, CRV, PEPE, ...), which then gets wrongly
floor-skipped. This module adds a SECOND-CHANCE valuation: read a wider, curated token set via Multicall3
and price it from DeFiLlama's free price API. It is used only to RESCUE a contract that fell below the
floor on majors alone, so the expensive path is bounded to sub-floor contracts.

Honest bound: this prices a curated ~30-token set, not literally every ERC-20 a contract could hold -
arbitrary token-balance discovery needs an indexer (Covalent/Moralis) we have no key for. It materially
widens coverage (most pools pair a major with a well-known token) without claiming to be exhaustive.

The floor is a gating heuristic, never a finding, so an external price source is acceptable here; a
CONFIRMED drain still requires the on-chain fork proof, which this does not touch.
"""
from __future__ import annotations

import json
import time
import urllib.request

DEFILLAMA_PRICE_URL = "https://coins.llama.fi/prices/current/"
PRICE_TTL = 600  # seconds

# Curated mid/large-cap ERC-20s on Ethereum mainnet: (symbol, address, decimals). Addresses are canonical.
EXTENDED_TOKENS: list[tuple[str, str, int]] = [
    ("LINK", "0x514910771AF9Ca656af840dff83E8264EcF986CA", 18),
    ("UNI", "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", 18),
    ("AAVE", "0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9", 18),
    ("MKR", "0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2", 18),
    ("CRV", "0xD533a949740bb3306d119CC777fa900bA034cd52", 18),
    ("LDO", "0x5A98FcBEA516Cf06857215779Fd812CA3beF1B32", 18),
    ("SNX", "0xC011a73ee8576Fb46F5E1c5751cA3B9Fe0af2a6F", 18),
    ("COMP", "0xc00e94Cb662C3520282E6f5717214004A7f26888", 18),
    ("SUSHI", "0x6B3595068778DD592e39A122f4f5a5cF09C90fE2", 18),
    ("1INCH", "0x111111111117dC0aa78b770fA6A738034120C302", 18),
    ("GRT", "0xc944E90C64B2c07662A292be6244BDf05Cda44a7", 18),
    ("FXS", "0x3432B6A60D23Ca0dFCa7761B7ab56459D9C964D0", 18),
    ("CVX", "0x4e3FBD56CD56c3e72c1403e103b45Db9da5B9D2B", 18),
    ("PENDLE", "0x808507121B80c02388fAd14726482e061B8da827", 18),
    ("PEPE", "0x6982508145454Ce325dDbE47a25d4ec3d2311933", 18),
    ("SHIB", "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE", 18),
    ("FRAX", "0x853d955aCEf822Db058eb8505911ED77F175b99e", 18),
    ("LUSD", "0x5f98805A4E8be255a32880FDeC7F6728C6568bA0", 18),
    ("GHO", "0x40D16FC0246aD3160Ccc09B8D0D3A2cD28aE6C2f", 18),
    ("crvUSD", "0xf939E0A03FB07F59A73314E73794Be0E57ac1b4E", 18),
    ("sDAI", "0x83F20F44975D03b1b09e64809B757c47f942BEeA", 18),
    ("rETH", "0xae78736Cd615f374D3085123A210448E74Fc6393", 18),
    ("cbETH", "0xBe9895146f7AF43049ca1c1AE358B0541Ea49704", 18),
    ("PYUSD", "0x6c3ea9036406852006290770BEdFcAbA0e23A0e8", 6),
    ("TUSD", "0x0000000000085d4780B73119b644AE5ecd22b376", 18),
    ("ENA", "0x57e114B691Db790C35207b2e685D4A43181e6061", 18),
    ("ENS", "0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72", 18),
    ("BAL", "0xba100000625a3754423978a60c9317c58a424e3D", 18),
    ("YFI", "0x0bc529c00C6401aEF6D220BE8C6Ea1667F6Ad93e", 18),
    ("APE", "0x4d224452801ACEd8B2F0aebE155379bb5D594381", 18),
]

_price_cache: dict[str, tuple[float, float]] = {}   # addr_lower -> (fetched_at, price)


def defillama_prices(addresses: list[str], chain: str = "ethereum", timeout: float = 15.0) -> dict[str, float]:
    """USD prices for the given token addresses from DeFiLlama, cached per-address for PRICE_TTL. A price
    that cannot be fetched is simply absent from the result (never guessed)."""
    now = time.time()
    out: dict[str, float] = {}
    missing: list[str] = []
    for a in addresses:
        al = a.lower()
        hit = _price_cache.get(al)
        if hit and now - hit[0] < PRICE_TTL:
            out[al] = hit[1]
        else:
            missing.append(al)
    if missing:
        try:
            url = DEFILLAMA_PRICE_URL + ",".join(f"{chain}:{a}" for a in missing)
            req = urllib.request.Request(url, headers={"User-Agent": "bountyscan/1.0", "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                coins = json.loads(r.read().decode("utf-8")).get("coins", {})
            for key, v in coins.items():
                al = key.split(":")[-1].lower()
                price = v.get("price")
                if isinstance(price, (int, float)) and price > 0:
                    _price_cache[al] = (now, float(price))
                    out[al] = float(price)
        except Exception:
            pass
    return out


def sum_priced(balances: dict[str, int], decimals: dict[str, int], prices: dict[str, float]) -> float:
    """Pure: USD value of raw token balances given per-token decimals and USD prices. Unpriced tokens
    contribute nothing (never guessed)."""
    total = 0.0
    for addr, raw in balances.items():
        al = addr.lower()
        if not raw or al not in prices or al not in decimals:
            continue
        total += (raw / 10 ** decimals[al]) * prices[al]
    return total


def extended_token_value_usd(rpc, address: str, tokens: list[tuple[str, str, int]] = None, chunk: int = 40) -> float:
    """USD value of `address`'s holdings of the EXTENDED_TOKENS set: balances via Multicall3, prices via
    DeFiLlama. Best-effort; returns 0.0 on any failure. Network-bound - call only to rescue a sub-floor
    contract, not on the hot path."""
    from .value import BALANCE_OF, MULTICALL3, _call, _word, decode_aggregate3, encode_aggregate3

    toks = tokens if tokens is not None else EXTENDED_TOKENS
    decimals = {t[1].lower(): t[2] for t in toks}
    pad = bytes.fromhex("0" * 24 + address.lower()[2:])
    balances: dict[str, int] = {}
    for i in range(0, len(toks), chunk):
        group = toks[i:i + chunk]
        calls = [(tok, bytes.fromhex(BALANCE_OF[2:]) + pad) for _, tok, _ in group]
        try:
            res = decode_aggregate3(_call(rpc, MULTICALL3, encode_aggregate3(calls)))
        except Exception:
            continue
        for (ok, data), (_, tok, _) in zip(res, group):
            if ok and len(data) >= 32:
                raw = int.from_bytes(data[:32], "big")
                if raw:
                    balances[tok.lower()] = raw
    if not balances:
        return 0.0
    prices = defillama_prices(list(balances.keys()))
    return sum_priced(balances, decimals, prices)
