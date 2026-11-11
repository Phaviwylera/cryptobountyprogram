"""Collect Solidity sources: local paths, git repos, and verified on-chain contracts."""
from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

DEFAULT_EXCLUDED_DIRS = {"node_modules", "lib", "test", "tests", "mock", "mocks", "script", "scripts", ".git", "cache", "out", "artifacts"}
EXCLUDED_SUFFIXES = (".t.sol", ".s.sol")

# Etherscan V2 unified API: one key, many chains.
ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
CHAIN_IDS = {
    "ethereum": 1, "mainnet": 1, "sepolia": 11155111,
    "bsc": 56, "polygon": 137, "arbitrum": 42161, "optimism": 10, "base": 8453,
    "avalanche": 43114, "linea": 59144, "scroll": 534352, "blast": 81457,
    "gnosis": 100, "fantom": 250, "mantle": 5000, "zksync": 324, "sonic": 146,
}
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def collect_files(paths: list[str | Path], include_deps: bool = False) -> list[Path]:
    """Expand files/directories into a sorted list of .sol files."""
    out: list[Path] = []
    for p in map(Path, paths):
        if p.is_file() and p.suffix == ".sol":
            out.append(p)
        elif p.is_dir():
            for root, dirs, files in os.walk(p):
                if not include_deps:
                    dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDED_DIRS]
                for name in files:
                    if name.endswith(".sol") and (include_deps or not name.endswith(EXCLUDED_SUFFIXES)):
                        out.append(Path(root) / name)
    return sorted(set(out))


def _safe_relpath(name: str) -> Path:
    """Turn an API-provided source path into a safe relative path (no traversal)."""
    parts = [p for p in PurePosixPath(name.replace("\\", "/")).parts if p not in ("", "/", ".", "..") and ":" not in p]
    return Path(*parts) if parts else Path("Contract.sol")


EXPLORERS = {
    1: "https://etherscan.io", 11155111: "https://sepolia.etherscan.io", 56: "https://bscscan.com",
    137: "https://polygonscan.com", 42161: "https://arbiscan.io", 10: "https://optimistic.etherscan.io",
    8453: "https://basescan.org", 43114: "https://snowtrace.io", 59144: "https://lineascan.build",
    534352: "https://scrollscan.com", 81457: "https://blastscan.io", 100: "https://gnosisscan.io",
    250: "https://ftmscan.com", 5000: "https://mantlescan.xyz", 324: "https://era.zksync.network", 146: "https://sonicscan.org",
}


class NotVerified(RuntimeError):
    """The contract exists but its source is not (yet) verified on the explorer."""


class ExplorerFatal(RuntimeError):
    """Bad API key / unsupported chain on this plan - retrying will not help."""


def chain_id_of(chain: str) -> int:
    key = chain.lower()
    if key.isdigit():
        return int(key)
    if key not in CHAIN_IDS:
        raise ValueError(f"unknown chain {chain!r}; use one of {sorted(CHAIN_IDS)} or a numeric chain id")
    return CHAIN_IDS[key]


def explorer_url(chain: str, address: str) -> str:
    base = EXPLORERS.get(chain_id_of(chain), "https://etherscan.io")
    return f"{base}/address/{address}#code"


_last_call = [0.0]


def _get_json(url: str, min_interval: float = 0.25) -> dict:
    """GET with Etherscan free-tier pacing (<= 5 req/s) and retry on rate-limit responses."""
    import time

    for attempt in range(4):
        wait = min_interval - (time.monotonic() - _last_call[0])
        if wait > 0:
            time.sleep(wait)
        _last_call[0] = time.monotonic()
        req = urllib.request.Request(url, headers={"User-Agent": "bountyscan/0.2"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if "rate limit" in str(data.get("result", "")).lower():
            time.sleep(1.5 * (attempt + 1))
            continue
        return data
    return data


def fetch_verified_source(address: str, chain: str, dest: Path, api_key: str | None = None, follow_proxy: bool = True) -> Path:
    """Download verified source from Etherscan (V2 API) into dest/<chain>/<address>/.

    Returns the directory containing the .sol files. Follows one level of proxy
    to the implementation when the explorer reports one.
    """
    if not ADDRESS_RE.match(address):
        raise ValueError(f"not an EVM address: {address!r}")
    chain_key = chain.lower()
    chain_id = chain_id_of(chain_key)
    out_dir = dest / chain_key / address.lower()
    if (out_dir / "bountyscan-meta.json").exists():
        return out_dir  # already fetched
    api_key = api_key or os.environ.get("ETHERSCAN_API_KEY")
    if not api_key:
        raise ExplorerFatal("set ETHERSCAN_API_KEY (free at https://etherscan.io/myapikey) or pass --api-key")

    query = urllib.parse.urlencode({
        "chainid": chain_id, "module": "contract", "action": "getsourcecode",
        "address": address, "apikey": api_key,
    })
    data = _get_json(f"{ETHERSCAN_V2}?{query}")
    if data.get("status") != "1" or not data.get("result"):
        msg = str(data.get("result") or data.get("message"))
        if re.search(r"api.?key|not supported|upgrade|plan", msg, re.I):
            raise ExplorerFatal(f"explorer refused the request: {msg}")
        raise RuntimeError(f"explorer error for {address}: {msg}")
    info = data["result"][0]
    source = info.get("SourceCode") or ""
    if not source:
        raise NotVerified(f"{address} on {chain} is not verified")

    out_dir.mkdir(parents=True, exist_ok=True)

    sources: dict[str, str]
    text = source.strip()
    if text.startswith("{{"):
        text = text[1:-1]  # standard-json-input wrapped in an extra brace
    if text.startswith("{"):
        parsed = json.loads(text)
        raw_sources = parsed.get("sources", parsed)
        sources = {k: (v.get("content", "") if isinstance(v, dict) else str(v)) for k, v in raw_sources.items()}
    else:
        sources = {f"{info.get('ContractName') or 'Contract'}.sol": source}

    for name, content in sources.items():
        target = out_dir / _safe_relpath(name)
        if out_dir.resolve() not in target.resolve().parents:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="")   # keep line endings exact (line numbers)

    meta = {
        "address": address, "chain": chain_key, "chain_id": chain_id,
        "contract_name": info.get("ContractName"), "compiler": info.get("CompilerVersion"),
        "proxy": info.get("Proxy") == "1", "implementation": info.get("Implementation") or None,
    }
    impl = meta["implementation"]
    if follow_proxy and meta["proxy"] and impl and ADDRESS_RE.match(impl) and impl.lower() != address.lower():
        try:
            fetch_verified_source(impl, chain, out_dir / "implementation", api_key, follow_proxy=False)
        except NotVerified:
            meta["implementation_unverified"] = True
    # written last: its presence marks a complete, reusable download
    (out_dir / "bountyscan-meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return out_dir


def read_meta(source_dir: Path) -> dict:
    try:
        return json.loads((source_dir / "bountyscan-meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# ---------------------------------------------------------------- Blockscout (no API key)
BLOCKSCOUT = {
    1: "https://eth.blockscout.com", 8453: "https://base.blockscout.com", 42161: "https://arbitrum.blockscout.com",
    10: "https://optimism.blockscout.com", 137: "https://polygon.blockscout.com", 100: "https://gnosis.blockscout.com",
    534352: "https://scroll.blockscout.com", 11155111: "https://eth-sepolia.blockscout.com",
}
_bs_last = [0.0]
_bs_lock = __import__("threading").Lock()


def _bs_get(url: str, min_interval: float = 0.25) -> dict:
    """GET a Blockscout API URL, politely paced (~4 req/s across all threads), retrying on rate limits."""
    import time
    import urllib.error

    for attempt in range(5):
        with _bs_lock:
            wait = min_interval - (time.monotonic() - _bs_last[0])
            if wait > 0:
                time.sleep(wait)
            _bs_last[0] = time.monotonic()
        req = urllib.request.Request(url, headers={"User-Agent": "bountyscan/0.8", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise NotVerified(url) from exc
            if exc.code in (429, 500, 502, 503, 504) and attempt < 4:
                time.sleep(2 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            if attempt < 4:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    return {}


def blockscout_base(chain: str) -> str:
    cid = chain_id_of(chain)
    if cid not in BLOCKSCOUT:
        raise ValueError(f"no Blockscout instance configured for {chain}")
    return BLOCKSCOUT[cid]


def blockscout_verified_page(chain: str, cursor: int | None) -> tuple[list[dict], int | None]:
    """One page (50) of verified contracts, newest first. Returns (items, next_cursor)."""
    url = f"{blockscout_base(chain)}/api/v2/smart-contracts"
    if cursor:
        url += f"?smart_contract_id={int(cursor)}&items_count=50"
    data = _bs_get(url)
    npp = data.get("next_page_params") or {}
    return data.get("items") or [], (int(npp["smart_contract_id"]) if npp.get("smart_contract_id") else None)


def fetch_blockscout_source(address: str, chain: str, dest: Path, follow_proxy: bool = True) -> Path:
    """Verified source from Blockscout into dest/<chain>/<address>/ (same layout as the Etherscan fetch).
    Follows one level of proxy to its implementation. No API key, no Etherscan quota."""
    if not ADDRESS_RE.match(address):
        raise ValueError(f"not an EVM address: {address!r}")
    out_dir = dest / chain.lower() / address.lower()
    if (out_dir / "bountyscan-meta.json").exists():
        return out_dir
    d = _bs_get(f"{blockscout_base(chain)}/api/v2/smart-contracts/{address}")
    if not d.get("is_verified") or not (d.get("source_code") or d.get("additional_sources")):
        raise NotVerified(f"{address} not verified on Blockscout")
    if (d.get("language") or "solidity").lower() != "solidity":
        raise NotVerified(f"{address} is {d.get('language')}, not Solidity")
    out_dir.mkdir(parents=True, exist_ok=True)
    files = [(d.get("file_path") or f"{d.get('name') or 'Contract'}.sol", d.get("source_code") or "")]
    files += [(s.get("file_path") or "extra.sol", s.get("source_code") or "") for s in (d.get("additional_sources") or [])]
    for name, content in files:
        if not name.endswith(".sol"):
            name += ".sol"
        target = out_dir / _safe_relpath(name)
        if out_dir.resolve() not in target.resolve().parents:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="")
    impls = [i.get("address_hash") for i in (d.get("implementations") or []) if i.get("address_hash")]
    meta = {"address": address, "chain": chain.lower(), "chain_id": chain_id_of(chain), "source": "blockscout",
            "contract_name": d.get("name"), "compiler": d.get("compiler_version"),
            "proxy": bool(d.get("proxy_type")), "implementation": impls[0] if impls else None}
    if follow_proxy and impls and ADDRESS_RE.match(impls[0]) and impls[0].lower() != address.lower():
        try:
            fetch_blockscout_source(impls[0], chain, out_dir / "implementation", follow_proxy=False)
        except (NotVerified, ValueError):
            meta["implementation_unverified"] = True
    (out_dir / "bountyscan-meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return out_dir


def clone_repo(url: str, dest: Path, ref: str | None = None) -> Path:
    """Shallow-clone a git repo (https only) into dest/<name>."""
    if not url.startswith("https://"):
        raise ValueError("only https:// git URLs are supported")
    name = re.sub(r"\.git$", "", url.rstrip("/").split("/")[-1]) or "repo"
    target = dest / name
    if target.exists():
        return target
    cmd = ["git", "clone", "--depth", "1"] + (["--branch", ref] if ref else []) + ["--", url, str(target)]
    subprocess.run(cmd, check=True)
    return target
