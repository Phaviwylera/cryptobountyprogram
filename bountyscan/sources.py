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
        target.write_text(content, encoding="utf-8")

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
