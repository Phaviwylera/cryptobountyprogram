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


def parse_protocol_rows(protocols: list, min_tvl_usd: float, chain: str = "Ethereum") -> list[dict]:
    """Like parse_protocol_addresses, but each qualifying protocol as {address, name, tvl} - for the audit
    name map. Same chain + TVL filter + address validation; deduplicated by address, order kept."""
    out: list[dict] = []
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
            out.append({"address": addr, "name": p.get("name"), "tvl": tvl})
    return out


def defillama_addresses(min_tvl_usd: float = 100_000.0, chain: str = "Ethereum", timeout: float = 40.0) -> list[str]:
    """Fetch and parse: validated contract addresses of `chain` protocols with TVL >= min_tvl_usd."""
    return parse_protocol_addresses(_fetch_protocols(timeout), min_tvl_usd, chain)


def defillama_rows(min_tvl_usd: float = 100_000.0, chain: str = "Ethereum", timeout: float = 40.0) -> list[dict]:
    """Fetch and parse: {address, name, tvl} rows of `chain` protocols with TVL >= min_tvl_usd.

    NOTE: DeFiLlama's `address` field is a protocol's GOVERNANCE TOKEN, not its TVL-bearing pool/vault
    contracts. Scanning those tokens says nothing about a protocol's custody contracts, so the live window
    uses custody_addresses() below instead. Kept for reference / non-custody uses."""
    return parse_protocol_rows(_fetch_protocols(timeout), min_tvl_usd, chain)


# ---------------------------------------------------------------------------------------------
# Custody-contract resolution (Ethereum mainnet): enumerate the ACTUAL pool/vault contracts that
# hold TVL from canonical protocol factories/registries, via read-only eth_call (no API key). Every
# selector below was validated live on-chain. The per-contract USD floor in the scan pipeline is the
# authoritative TVL filter; this just points the scanner at custody contracts instead of tokens.
COMPTROLLER = "0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B"        # Compound v2 Comptroller
CURVE_REGISTRY = "0x90E00ACe148ca3b23Ac1bC8C240C2a7Dd9c2d7f5"    # Curve main registry
AAVE_V3_POOL = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"       # Aave v3 Pool
UNIV2_FACTORY = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"      # Uniswap V2 Factory

SEL_GET_ALL_MARKETS = "b0772d0b"     # Compound getAllMarkets() -> address[]
SEL_POOL_COUNT = "956aae3a"          # Curve pool_count() -> uint256
SEL_POOL_LIST = "3a1d5d8e"           # Curve pool_list(uint256) -> address
SEL_GET_RESERVES_LIST = "d1946dbc"   # Aave getReservesList() -> address[]
SEL_GET_RESERVE_DATA = "35ea6a75"    # Aave getReserveData(address) -> struct (aToken at word 8)
SEL_ALL_PAIRS_LENGTH = "574f2ba3"    # UniV2 allPairsLength() -> uint256
SEL_ALL_PAIRS = "1e3dd18b"           # UniV2 allPairs(uint256) -> address


def decode_address_array(hexstr: str) -> list[str]:
    """Decode an ABI-encoded address[] return value into lower-case 0x addresses."""
    h = hexstr[2:] if hexstr.startswith("0x") else hexstr
    if len(h) < 128:
        return []
    off = int(h[0:64], 16) * 2
    n = int(h[off:off + 64], 16)
    base = off + 64
    out = []
    for i in range(n):
        w = h[base + i * 64: base + (i + 1) * 64]
        if len(w) == 64:
            out.append("0x" + w[-40:])
    return out


def _nonzero_addr(word_bytes: bytes) -> str | None:
    if len(word_bytes) < 32:
        return None
    a = "0x" + word_bytes[-20:].hex()
    return a if int(a, 16) != 0 else None


def custody_addresses(rpc_url: str, univ2_max: int = 500, curve_max: int = 200) -> list[dict]:
    """Enumerate custody contracts (Compound cTokens, Curve pools, Aave aTokens, Uniswap V2 pairs) via
    read-only eth_call + Multicall3. Returns {address, name, source} rows, deduped. Best-effort per source:
    a source that fails is skipped, never raising. Network-bound; call off the hot path (every few hours)."""
    from .rpc import RPC
    from .value import MULTICALL3, _call, _word, decode_aggregate3, encode_aggregate3

    rpc = RPC(rpc_url)
    rows: list[dict] = []
    seen: set[str] = set()

    def add(addr: str | None, name: str, source: str):
        if not addr:
            return
        a = addr.lower()
        if len(a) == 42 and a not in seen and int(a, 16) != 0:
            seen.add(a)
            rows.append({"address": a, "name": name, "source": source})

    def multicall(calls):
        out = []
        for i in range(0, len(calls), 40):
            group = calls[i:i + 40]
            try:
                out += decode_aggregate3(_call(rpc, MULTICALL3, encode_aggregate3(group)))
            except Exception:
                out += [(False, b"")] * len(group)
        return out

    try:                                   # Compound cTokens
        for a in decode_address_array(_call(rpc, COMPTROLLER, "0x" + SEL_GET_ALL_MARKETS)):
            add(a, "Compound cToken", "compound")
    except Exception:
        pass
    try:                                   # Curve pools
        n = int(_call(rpc, CURVE_REGISTRY, "0x" + SEL_POOL_COUNT), 16)
        calls = [(CURVE_REGISTRY, bytes.fromhex(SEL_POOL_LIST) + bytes.fromhex(_word(i))) for i in range(min(n, curve_max))]
        for ok, data in multicall(calls):
            if ok:
                add(_nonzero_addr(data), "Curve pool", "curve")
    except Exception:
        pass
    try:                                   # Aave v3 aTokens (custody), resolved from each reserve
        reserves = decode_address_array(_call(rpc, AAVE_V3_POOL, "0x" + SEL_GET_RESERVES_LIST))
        calls = [(AAVE_V3_POOL, bytes.fromhex(SEL_GET_RESERVE_DATA) + bytes.fromhex(_word(int(a, 16)))) for a in reserves]
        for ok, data in multicall(calls):
            if ok and len(data) >= 9 * 32:
                add(_nonzero_addr(data[8 * 32:9 * 32]), "Aave aToken", "aave")
    except Exception:
        pass
    try:                                   # Uniswap V2 pairs (bounded; homogeneous source dedups in-scan)
        total = int(_call(rpc, UNIV2_FACTORY, "0x" + SEL_ALL_PAIRS_LENGTH), 16)
        calls = [(UNIV2_FACTORY, bytes.fromhex(SEL_ALL_PAIRS) + bytes.fromhex(_word(i))) for i in range(min(total, univ2_max))]
        for ok, data in multicall(calls):
            if ok:
                add(_nonzero_addr(data), "Uniswap V2 pair", "univ2")
    except Exception:
        pass
    return rows
