"""Bounty-program runs: fetch every in-scope asset from a scope file, scan, and write reports."""
from __future__ import annotations

import json
from pathlib import Path

from .scanner import ScanResult, scan
from .sources import clone_repo, fetch_verified_source

REQUIRED_KEYS = {"program", "assets"}


def load_scope(path: Path) -> dict:
    scope = json.loads(path.read_text(encoding="utf-8"))
    missing = REQUIRED_KEYS - scope.keys()
    if missing:
        raise ValueError(f"{path}: missing keys {sorted(missing)}")
    for i, a in enumerate(scope["assets"]):
        if not ({"address", "path", "git"} & a.keys()):
            raise ValueError(f"{path}: asset #{i} needs one of address/path/git")
        if "address" in a and "chain" not in a:
            raise ValueError(f"{path}: asset #{i} has an address but no chain")
    return scope


def resolve_assets(scope: dict, scope_dir: Path, cache: Path, api_key: str | None) -> tuple[list[Path], list[str]]:
    paths, errors = [], []
    for a in scope["assets"]:
        label = a.get("name") or a.get("address") or a.get("path") or a.get("git")
        try:
            if "address" in a:
                paths.append(fetch_verified_source(a["address"], a["chain"], cache / "onchain", api_key))
            elif "git" in a:
                repo = clone_repo(a["git"], cache / "repos", a.get("ref"))
                paths.append(repo / a.get("subdir", ""))
            else:
                p = Path(a["path"])
                paths.append(p if p.is_absolute() else scope_dir / p)
        except Exception as exc:
            errors.append(f"asset {label}: {exc}")
    return paths, errors


def run_program(scope_path: Path, cache: Path, api_key: str | None = None, **scan_kwargs) -> tuple[dict, ScanResult]:
    scope = load_scope(scope_path)
    paths, errors = resolve_assets(scope, scope_path.parent, cache, api_key)
    result = scan(paths, **scan_kwargs) if paths else ScanResult([], [], [])
    result.errors = errors + result.errors
    meta = {k: v for k, v in scope.items() if k != "assets"}
    return meta, result
