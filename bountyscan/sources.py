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


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "bountyscan/0.1"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_verified_source(address: str, chain: str, dest: Path, api_key: str | None = None, follow_proxy: bool = True) -> Path:
    """Download verified source from Etherscan (V2 API) into dest/<chain>/<address>/.

    Returns the directory containing the .sol files. Follows one level of proxy
    to the implementation when the explorer reports one.
    """
    if not ADDRESS_RE.match(address):
        raise ValueError(f"not an EVM address: {address!r}")
    chain_key = chain.lower()
    if chain_key not in CHAIN_IDS and not chain_key.isdigit():
        raise ValueError(f"unknown chain {chain!r}; use one of {sorted(CHAIN_IDS)} or a numeric chain id")
    chain_id = int(chain_key) if chain_key.isdigit() else CHAIN_IDS[chain_key]
    api_key = api_key or os.environ.get("ETHERSCAN_API_KEY")
    if not api_key:
        raise RuntimeError("set ETHERSCAN_API_KEY (free at https://etherscan.io/myapikey) or pass --api-key")

    query = urllib.parse.urlencode({
        "chainid": chain_id, "module": "contract", "action": "getsourcecode",
        "address": address, "apikey": api_key,
    })
    data = _get_json(f"{ETHERSCAN_V2}?{query}")
    if data.get("status") != "1" or not data.get("result"):
        raise RuntimeError(f"explorer error for {address}: {data.get('result') or data.get('message')}")
    info = data["result"][0]
    source = info.get("SourceCode") or ""
    if not source:
        raise RuntimeError(f"{address} on {chain} is not verified")

    out_dir = dest / chain_key / address.lower()
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
    (out_dir / "bountyscan-meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    impl = meta["implementation"]
    if follow_proxy and meta["proxy"] and impl and ADDRESS_RE.match(impl) and impl.lower() != address.lower():
        fetch_verified_source(impl, chain, out_dir / "implementation", api_key, follow_proxy=False)
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
