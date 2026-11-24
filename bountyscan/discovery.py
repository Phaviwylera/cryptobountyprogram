"""Value-weighted target discovery.

The old live source enqueued EVERY newly-deployed contract - overwhelmingly test deployments
(MockToken, CustomToken, ...) with no funds. This source instead starts from protocols that actually
hold value: DeFiLlama's protocol list, filtered to a chain and a TVL floor, resolved to each protocol's
on-chain contract address. The per-contract USD floor in the scan pipeline (value.holdings) is the
second, authoritative filter - this just stops us wasting the window on contracts that were never going
to hold anything.

No API key, read-only HTTP (api.llama.fi is public). DeFiLlama is a third-party source: every value and
address it returns is validated here (TVL is numeric, address matches the EVM address shape) before it
reaches the queue, and nothing it returns is ever executed.
"""
from __future__ import annotations

import json
import urllib.request

from .sources import ADDRESS_RE

DEFILLAMA_PROTOCOLS = "https://api.llama.fi/protocols"

# internal chain name -> DeFiLlama's chain label
_LLAMA_CHAIN = {"ethereum": "Ethereum", "mainnet": "Ethereum"}


def llama_chain_name(chain: str) -> str:
    return _LLAMA_CHAIN.get(chain.lower(), chain.capitalize())


def _eth_address(raw) -> str | None:
    """A DeFiLlama `address` is 'ethereum:0x..', a bare '0x..', or null. Return a validated 0x.. or None."""
    if not raw or not isinstance(raw, str):
        return None
    addr = raw.split(":")[-1].strip().lower()
    return addr if ADDRESS_RE.match(addr) else None


def _fetch_protocols(timeout: float) -> list:
    req = urllib.request.Request(DEFILLAMA_PROTOCOLS,
                                 headers={"User-Agent": "bountyscan/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read().decode("utf-8"))
    return data if isinstance(data, list) else []


def parse_protocol_addresses(protocols: list, min_tvl_usd: float, chain: str = "Ethereum") -> list[str]:
    """Pure: given DeFiLlama's /protocols payload, return the validated contract addresses of protocols
    on `chain` whose TVL (on that chain, else overall) is at least the floor. Deduplicated, order kept."""
    out: list[str] = []
    seen: set[str] = set()
    for p in protocols:
        if not isinstance(p, dict):
            continue
        if chain not in (p.get("chains") or []):
            continue
        tvl = (p.get("chainTvls") or {}).get(chain)
        if tvl is None:
            tvl = p.get("tvl")
        try:
            tvl = float(tvl or 0)
        except (TypeError, ValueError):
            tvl = 0.0
        if tvl < min_tvl_usd:
            continue
        addr = _eth_address(p.get("address"))
        if addr and addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


def defillama_addresses(min_tvl_usd: float = 100_000.0, chain: str = "Ethereum", timeout: float = 40.0) -> list[str]:
    """Fetch and parse: validated contract addresses of `chain` protocols with TVL >= min_tvl_usd."""
    return parse_protocol_addresses(_fetch_protocols(timeout), min_tvl_usd, chain)
