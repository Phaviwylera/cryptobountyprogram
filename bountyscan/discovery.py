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


# ---- extended resolvers: periphery / newer DeFi primitives (higher bug density) --------------------
CONVEX_BOOSTER = "0xF403C135812408BFbE8713b5A23a04b3D48AAE31"
UNIV3_FACTORY = "0x1F98431c8aD98523631AE4a59f267346ea31F984"
BALANCER_VAULT = "0xBA12222222228d8Ba445958a75a0704d566BF2C8"

SEL_POOL_LENGTH = "081e3eda"         # Convex Booster poolLength() -> uint256
SEL_POOL_INFO = "1526fe27"           # Convex Booster poolInfo(uint256) -> (lptoken,token,gauge,crvRewards,stash,shutdown)
# event topic0 (keccak of the event signature), both publicly documented and validated on-chain before deploy:
TOPIC_POOL_CREATED = "0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118"   # UniV3 PoolCreated(...)
TOPIC_POOL_REGISTERED = "0x3c13bc30b8e878c53fd2a36b679409c073afd75950be43d8858768e956fbc20e"  # Balancer PoolRegistered
# ERC-4626 detection selectors
SEL_ASSET = "38d52e0f"                # asset() -> address
SEL_CONVERT_TO_SHARES = "c6e6f592"    # convertToShares(uint256) -> uint256


def _rpc_post(rpc_url: str, method: str, params, timeout: float = 30.0):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(rpc_url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read().decode("utf-8"))
    if "error" in d:
        raise RuntimeError(str(d["error"])[:120])
    return d.get("result")


def _block_number(rpc_url: str) -> int:
    return int(_rpc_post(rpc_url, "eth_blockNumber", []), 16)


def _logs_pool_addresses(rpc_url: str, address: str, topic0: str, blocks_back: int, max_pools: int,
                         extract, window: int = 9000) -> list[str]:
    """Collect addresses from `address`'s `topic0` logs over the last `blocks_back` blocks (chunked), using
    `extract(log) -> address|None`. Bounded by max_pools. Best-effort: a failing window is skipped."""
    out: list[str] = []
    seen: set[str] = set()
    try:
        head = _block_number(rpc_url)
    except Exception:
        return out
    frm = max(0, head - blocks_back)
    b = frm
    while b <= head and len(out) < max_pools:
        to = min(b + window, head)
        try:
            logs = _rpc_post(rpc_url, "eth_getLogs",
                             [{"address": address, "topics": [topic0], "fromBlock": hex(b), "toBlock": hex(to)}])
            for lg in logs or []:
                a = extract(lg)
                if a and a not in seen:
                    seen.add(a)
                    out.append(a)
                    if len(out) >= max_pools:
                        break
        except Exception:
            pass
        b = to + 1
    return out


def univ3_pool_addresses(rpc_url: str, blocks_back: int = 300_000, max_pools: int = 1500) -> list[str]:
    """Uniswap V3 pools from recent PoolCreated events (the pool address is the last 32-byte word of data)."""
    def extract(lg):
        data = lg.get("data", "")
        h = data[2:] if data.startswith("0x") else data
        return ("0x" + h[-40:]) if len(h) >= 64 else None
    return _logs_pool_addresses(rpc_url, UNIV3_FACTORY, TOPIC_POOL_CREATED, blocks_back, max_pools, extract)


def balancer_pool_addresses(rpc_url: str, blocks_back: int = 400_000, max_pools: int = 1000) -> list[str]:
    """Balancer v2 pools from recent PoolRegistered events (poolId topic's first 20 bytes = pool address)."""
    def extract(lg):
        topics = lg.get("topics", [])
        if len(topics) >= 2:
            pid = topics[1][2:] if topics[1].startswith("0x") else topics[1]
            return "0x" + pid[:40]
        return None
    return _logs_pool_addresses(rpc_url, BALANCER_VAULT, TOPIC_POOL_REGISTERED, blocks_back, max_pools, extract)


def convex_reward_pools(rpc_url: str, max_pools: int = 400) -> list[str]:
    """Convex staking (BaseRewardPool) contracts from the Booster: poolInfo(i).crvRewards (word 3)."""
    from .rpc import RPC
    from .value import MULTICALL3, _call, _word, decode_aggregate3, encode_aggregate3
    rpc = RPC(rpc_url)
    out: list[str] = []
    seen: set[str] = set()
    try:
        n = int(_call(rpc, CONVEX_BOOSTER, "0x" + SEL_POOL_LENGTH), 16)
    except Exception:
        return out
    idxs = list(range(min(n, max_pools)))
    for i in range(0, len(idxs), 40):
        group = idxs[i:i + 40]
        calls = [(CONVEX_BOOSTER, bytes.fromhex(SEL_POOL_INFO) + bytes.fromhex(_word(j))) for j in group]
        try:
            res = decode_aggregate3(_call(rpc, MULTICALL3, encode_aggregate3(calls)))
        except Exception:
            continue
        for ok, data in res:
            if ok and len(data) >= 4 * 32:
                a = "0x" + data[3 * 32 + 12:4 * 32].hex()   # crvRewards = word 3
                if int(a, 16) != 0 and a not in seen:
                    seen.add(a)
                    out.append(a)
    return out


def is_erc4626(rpc_url: str, address: str) -> bool:
    """True if `address` looks like an ERC-4626 vault: asset() returns an address and convertToShares(1e18)
    returns a value without reverting. Read-only; best-effort (False on any error)."""
    try:
        asset = _rpc_post(rpc_url, "eth_call", [{"to": address, "data": "0x" + SEL_ASSET}, "latest"])
        if not asset or len(asset) < 66 or int(asset, 16) == 0:
            return False
        shares = _rpc_post(rpc_url, "eth_call",
                           [{"to": address, "data": "0x" + SEL_CONVERT_TO_SHARES + "%064x" % (10 ** 18)}, "latest"])
        return bool(shares and shares != "0x" and len(shares) >= 66)
    except Exception:
        return False


def recent_verified_addresses(chain: str = "ethereum", pages: int = 4) -> list[str]:
    """Most-recently-verified contracts (the 'new, un-audited code' universe) via Blockscout's verified
    list, newest first. The TVL floor filters these at scan time. Best-effort."""
    from .sources import blockscout_verified_page
    out: list[str] = []
    seen: set[str] = set()
    cursor = None
    for _ in range(max(1, pages)):
        try:
            items, cursor = blockscout_verified_page(chain, cursor)
        except Exception:
            break
        for it in items or []:
            # Blockscout v2 nests the address: {"address": {"hash": "0x.."}}; tolerate flat forms too.
            af = it.get("address")
            if isinstance(af, dict):
                a = (af.get("hash") or "").lower()
            else:
                a = (af or it.get("address_hash") or it.get("hash") or "").lower()
            if ADDRESS_RE.match(a) and a not in seen:
                seen.add(a)
                out.append(a)
        if not cursor:
            break
    return out


def custody_addresses(rpc_url: str, univ2_max: int = 500, curve_max: int = 200,
                      include_periphery: bool = False, include_logs: bool = False, univ3_max: int = 1500,
                      balancer_max: int = 1000, convex_max: int = 400) -> list[dict]:
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
    if include_periphery:
        # Convex reward pools: enumerable via eth_call (no getLogs needed). Each wrapped so one failing
        # source never sinks the others.
        for a in convex_reward_pools(rpc_url, max_pools=convex_max):
            add(a, "Convex reward pool", "convex")
    if include_logs:
        # UniV3 / Balancer need eth_getLogs over block ranges the box's free RPC refuses ("max range"
        # limit). Off by default; enable only on a getLogs-capable RPC.
        for a in balancer_pool_addresses(rpc_url, max_pools=balancer_max):
            add(a, "Balancer pool", "balancer")
        for a in univ3_pool_addresses(rpc_url, max_pools=univ3_max):
            add(a, "Uniswap V3 pool", "univ3")
    return rows
