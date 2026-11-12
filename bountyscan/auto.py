"""Automatic mode: queue contracts, scan each one, mark SAFE / VULNERABLE, move to the next.

Sources of contracts:
  * address lists (one `[chain:]0x...` per line)
  * bounty program scope files (programs/*.json)
  * block ranges / live watch: every contract deployed by a transaction (via JSON-RPC)

Only fund-theft findings (critical/high in remediation.FUND_THEFT) mark a contract VULNERABLE.
Everything is read-only: sources come from the explorer, balances from eth_getBalance.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

from .contract_report import write_contract_report, write_summary
from .detectors import SEVERITY_RANK
from .remediation import is_fund_theft
from .rpc import RPC, RPCError
from .scanner import relevant_contracts, scan
from .sources import (ADDRESS_RE, ExplorerFatal, NotVerified, chain_id_of, fetch_blockscout_source,
                      fetch_verified_source, read_meta)
from .value import describe as describe_value, holdings as read_holdings
from .verifier import confirmed_findings, verify_findings

WEI = 10**18


@dataclass
class AutoConfig:
    out_dir: Path
    cache_dir: Path
    api_key: str | None = None
    rpc: RPC | None = None
    min_balance_wei: int = 0
    min_value_usd: float = 0.0     # skip contracts holding less than this (native + major tokens, USD)
    max_attempts: int = 6         # unverified retries before giving up
    retry_base: float = 600.0      # seconds; doubles each attempt (10m, 20m, 40m, ...)
    verify: bool = True            # independent second pass must confirm each finding
    forge_verify: bool = True      # dynamic third pass: run the exploit payload on a fork (needs forge + rpc)
    quiet: bool = False
    on_stage: object = None        # optional callback(stage_text) - the dashboard's live step display
    on_event: object = None        # optional callback(kind, message) - the dashboard's activity feed


def _stage(cfg: AutoConfig, text: str) -> None:
    if callable(cfg.on_stage):
        try:
            cfg.on_stage(text)
        except Exception:
            pass


def _event(cfg: AutoConfig, kind: str, msg: str) -> None:
    if callable(cfg.on_event):
        try:
            cfg.on_event(kind, msg)
        except Exception:
            pass


def parse_address_lines(text: str, default_chain: str) -> list[tuple[str, str]]:
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^(?:([A-Za-z0-9_-]+)\s*[:,\s]\s*)?(0x[0-9a-fA-F]{40})$", line)
        if not m:
            raise ValueError(f"bad address line: {raw!r} (expected `0x...` or `chain:0x...`)")
        out.append(((m.group(1) or default_chain).lower(), m.group(2)))
    return out


def _log(cfg: AutoConfig, msg: str) -> None:
    if not cfg.quiet:
        print(msg, flush=True)


def process(store, row, cfg: AutoConfig) -> str:
    chain, address = row["chain"], row["address"]

    balance = None
    held = None
    short = f"{address[:8]}…{address[-4:]}"
    if cfg.rpc is not None:
        _stage(cfg, f"Checking code & value held by {short}")
        try:
            if cfg.rpc.code(address) in ("0x", "0x0", ""):
                store.update(chain, address, status="no_code")
                return "no_code"
            balance = cfg.rpc.balance(address)
            held = read_holdings(cfg.rpc, chain_id_of(chain), address, balance)
        except (RPCError, ValueError) as exc:
            _log(cfg, f"    rpc warning: {exc}")
        value_fields = value_columns(held)
        too_little = (balance is not None and balance < cfg.min_balance_wei) or \
            (cfg.min_value_usd > 0 and held is not None and held["usd"] is not None and held["usd"] < cfg.min_value_usd)
        if too_little:
            store.update(chain, address, status="low_value", balance_wei=None if balance is None else str(balance), **value_fields)
            return "low_value"
    else:
        value_fields = {}

    backfill = (row["origin"] or "").startswith("backfill")
    _stage(cfg, f"Fetching verified source of {short}" + (" from Blockscout" if backfill else " from the explorer"))
    try:
        if backfill:
            # Blockscout listed it as verified: read source there (no Etherscan quota), Etherscan as fallback.
            try:
                src = fetch_blockscout_source(address, chain, cfg.cache_dir / "onchain")
            except (NotVerified, ValueError, OSError):
                src = fetch_verified_source(address, chain, cfg.cache_dir / "onchain", cfg.api_key)
        else:
            src = fetch_verified_source(address, chain, cfg.cache_dir / "onchain", cfg.api_key)
    except NotVerified:
        attempts = row["attempts"] + 1
        if backfill or attempts >= cfg.max_attempts:   # months-old and still unverified: will not change
            store.update(chain, address, status="unverified_final", attempts=attempts)
            return "unverified_final"
        store.update(chain, address, status="unverified", attempts=attempts,
                     next_try=time.time() + cfg.retry_base * 2 ** (attempts - 1))
        return "unverified"

    meta = read_meta(src)
    name = meta.get("contract_name") or ""

    # Identical source already judged SAFE (clones, factory pairs): reuse the verdict, skip the scan.
    shash = source_hash(src)
    hit = store.cached_verdict(shash) if hasattr(store, "cached_verdict") else None
    if hit and hit[0] == "safe":
        store.update(chain, address, status="safe", name=name, findings=0, max_severity=None,
                     balance_wei=None if balance is None else str(balance),
                     error=f"(identical source to {hit[1]})", **value_fields)
        _discard_source(src, cfg)
        return "safe"

    _stage(cfg, f"Scanning {name or short} with all fund-theft detectors")
    result = scan([src], min_severity="high", meta=meta)
    # Only the deployed contract (and, for a proxy, its implementation) plus what they inherit count.
    roots = [meta.get("contract_name")]
    impl_meta = read_meta(src / "implementation" / chain / str(meta.get("implementation") or "").lower()) \
        if meta.get("implementation") else {}
    roots.append(impl_meta.get("contract_name"))
    keep = relevant_contracts(result.files, [r for r in roots if r])
    candidates = [f for f in result.findings if is_fund_theft(f) and (keep is None or f.contract in keep)]

    theft = candidates
    verdicts = None
    if candidates and cfg.verify:
        _stage(cfg, f"Independently re-verifying {len(candidates)} candidate(s) in {name or short}")
        try:
            verdicts = verify_findings(candidates, chain, address, cfg.cache_dir, cfg.api_key)
            theft = confirmed_findings(verdicts)
        except Exception as exc:
            _log(cfg, f"    verification warning ({exc}); holding findings for manual review")
            theft = []  # unconfirmed -> do not claim vulnerable
    # Dynamic third pass: actually run each surviving finding's exploit PAYLOAD on a mainnet fork.
    # A payload that reverts or moves no funds/state is NOT a finding and is dropped here.
    payloads = None
    payload_note = ""
    if theft and cfg.forge_verify and cfg.rpc is not None:
        from .forge_verify import forge_available, run_payloads
        if forge_available():
            _stage(cfg, f"Launching payload attack on {len(theft)} finding(s) on a {chain} fork")
            try:
                payloads = run_payloads(theft, result.files, address, cfg.rpc.url)
                kept = [pv.finding for pv in payloads if pv.is_finding]
                dropped = len(theft) - len(kept)
                conf = sum(pv.outcome == "confirmed" for pv in payloads)
                if dropped:
                    _log(cfg, f"    payload attack disproved {dropped} finding(s) (reverted / no funds moved)")
                payload_note = f" ({dropped} disproved by payload attack)" if dropped else ""
                theft = kept
                if conf:
                    _log(cfg, f"    payload attack CONFIRMED {conf} finding(s)")
            except Exception as exc:
                _log(cfg, f"    payload attack warning ({exc}); keeping static verdicts")

    if not theft:
        extra = ""
        if candidates and (verdicts is not None):
            extra = f" ({len(candidates)} candidate(s) not confirmed by second pass{payload_note})"
        store.update(chain, address, status="safe", name=name, findings=0, max_severity=None,
                     balance_wei=None if balance is None else str(balance), error=extra or None, **value_fields)
        if hasattr(store, "cache_verdict"):
            store.cache_verdict(shash, "safe", address)
        _discard_source(src, cfg)
        return "safe"

    report = write_contract_report(chain, address, meta, theft, balance, src, cfg.out_dir,
                                   verdicts=verdicts, holdings=held, payloads=payloads)
    worst = min(theft, key=lambda f: SEVERITY_RANK[f.severity]).severity
    store.update(chain, address, status="vulnerable", name=name, findings=len(theft), max_severity=worst,
                 balance_wei=None if balance is None else str(balance), report=str(report), error=None, **value_fields)
    return "vulnerable"


def _discard_source(src: Path, cfg: AutoConfig) -> None:
    """SAFE contracts don't need their source kept: a 6-month backfill would otherwise fill the disk.
    Vulnerable ones keep theirs (the report quotes it). Only ever deletes inside the cache directory."""
    import shutil
    try:
        root = (Path(cfg.cache_dir) / "onchain").resolve()
        target = Path(src).resolve()
        if root in target.parents:
            shutil.rmtree(target, ignore_errors=True)
            shutil.rmtree((Path(cfg.cache_dir) / "verify").resolve() / target.parent.name / target.name, ignore_errors=True)
    except OSError:
        pass


def source_hash(src_dir: Path) -> str:
    """Stable hash of every .sol file (path + content) under a fetched source directory."""
    import hashlib
    h = hashlib.sha256()
    for p in sorted(Path(src_dir).rglob("*.sol")):
        h.update(p.relative_to(src_dir).as_posix().encode())
        h.update(b"\0")
        h.update(p.read_bytes().replace(b"\r\n", b"\n"))
        h.update(b"\0")
    return h.hexdigest()


def value_columns(held: dict | None) -> dict:
    """DB columns for a holdings snapshot (empty when value could not be read)."""
    if held is None:
        return {}
    import json
    return {"value_usd": held["usd"], "holdings": json.dumps(held["items"]), "value_checked": time.time()}


def recheck_value(store, row, rpc: RPC) -> tuple[float | None, float | None]:
    """Re-read what a contract holds now. Returns (old_usd, new_usd)."""
    old = row["value_usd"]
    bal = rpc.balance(row["address"])
    held = read_holdings(rpc, chain_id_of(row["chain"]), row["address"], bal)
    store.update(row["chain"], row["address"], balance_wei=str(bal), **value_columns(held))
    return old, held["usd"]


def _describe(status: str, store, chain: str, address: str) -> str:
    row = store.fetch_one(chain, address)
    bal = f"  {int(row['balance_wei']) / WEI:.4f} native" if row["balance_wei"] else ""
    name = f" {row['name']}" if row["name"] else ""
    if status == "vulnerable":
        return f"VULNERABLE ({row['findings']} fund-theft finding(s), worst: {row['max_severity']}){name}{bal} -> {row['report']}"
    if status == "safe":
        return f"SAFE{name}{bal}"
    if status == "unverified":
        return f"UNVERIFIED - will retry later (attempt {row['attempts']})"
    return {"low_value": f"SKIPPED (balance below threshold){bal}", "no_code": "SKIPPED (no code)",
            "unverified_final": "UNVERIFIED - gave up", "error": f"ERROR {row['error']}"}.get(status, status.upper())


def run_queue(store, cfg: AutoConfig, limit: int | None = None) -> dict[str, int]:
    """Process every contract that is due now. Returns per-status counts for this run."""
    tally: dict[str, int] = {}
    rows = store.due(limit)
    for i, row in enumerate(rows, 1):
        chain, address = row["chain"], row["address"]
        try:
            status = process(store, row, cfg)
        except ExplorerFatal:
            raise
        except Exception as exc:  # one bad contract never stops the run
            store.update(chain, address, status="error", error=str(exc)[:300])
            status = "error"
        tally[status] = tally.get(status, 0) + 1
        _log(cfg, f"[{i}/{len(rows)}] {chain} {address}  {_describe(status, store, chain, address)}")
    write_summary(store, cfg.out_dir)
    return tally


def discover_blocks(store, rpc: RPC, chain: str, start: int, end: int, cfg: AutoConfig) -> int:
    found = 0
    for n in range(start, end + 1):
        _stage(cfg, f"Reading block {n:,} on {chain} for new contract deployments")
        for addr in rpc.created_contracts(n):
            if ADDRESS_RE.match(addr) and store.enqueue(chain, addr, f"block:{n}"):
                found += 1
                _log(cfg, f"  + block {n}: new contract {addr}")
                _event(cfg, "found", f"New contract {addr} deployed in block {n:,}")
        store.set_cursor(chain, n)
    return found


def watch(store, rpc: RPC, chain: str, cfg: AutoConfig, poll: float = 15.0, from_block: int | None = None,
          max_blocks_per_poll: int = 50) -> None:
    """Follow the chain forever: discover new deployments, scan whatever is due, sleep, repeat."""
    cursor = store.cursor(chain)
    if from_block is not None:
        cursor = from_block - 1
    if cursor is None:
        cursor = rpc.block_number() - 1
    _log(cfg, f"Watching {chain} from block {cursor + 1} (Ctrl+C to stop; progress is saved).")
    while True:
        try:
            head = rpc.block_number()
            if head > cursor:
                end = min(head, cursor + max_blocks_per_poll)
                discover_blocks(store, rpc, chain, cursor + 1, end, cfg)
                cursor = end
            if store.due(1):
                run_queue(store, cfg)
        except RPCError as exc:
            _log(cfg, f"  rpc error, retrying: {exc}")
        try:
            caught_up = cursor >= rpc.block_number()
        except RPCError:
            caught_up = True
        if caught_up:
            time.sleep(poll)
