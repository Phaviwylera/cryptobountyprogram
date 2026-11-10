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
from .scanner import scan
from .sources import ADDRESS_RE, ExplorerFatal, NotVerified, fetch_verified_source, read_meta
from .verifier import confirmed_findings, verify_findings

WEI = 10**18


@dataclass
class AutoConfig:
    out_dir: Path
    cache_dir: Path
    api_key: str | None = None
    rpc: RPC | None = None
    min_balance_wei: int = 0
    max_attempts: int = 6          # unverified retries before giving up
    retry_base: float = 600.0      # seconds; doubles each attempt (10m, 20m, 40m, ...)
    verify: bool = True            # independent second pass must confirm each finding
    quiet: bool = False


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
    if cfg.rpc is not None:
        try:
            if cfg.rpc.code(address) in ("0x", "0x0", ""):
                store.update(chain, address, status="no_code")
                return "no_code"
            balance = cfg.rpc.balance(address)
        except RPCError as exc:
            balance = None
            _log(cfg, f"    rpc warning: {exc}")
        if balance is not None and balance < cfg.min_balance_wei:
            store.update(chain, address, status="low_value", balance_wei=str(balance))
            return "low_value"

    try:
        src = fetch_verified_source(address, chain, cfg.cache_dir / "onchain", cfg.api_key)
    except NotVerified:
        attempts = row["attempts"] + 1
        if attempts >= cfg.max_attempts:
            store.update(chain, address, status="unverified_final", attempts=attempts)
            return "unverified_final"
        store.update(chain, address, status="unverified", attempts=attempts,
                     next_try=time.time() + cfg.retry_base * 2 ** (attempts - 1))
        return "unverified"

    meta = read_meta(src)
    result = scan([src], min_severity="high")
    candidates = [f for f in result.findings if is_fund_theft(f)]
    name = meta.get("contract_name") or ""

    theft = candidates
    verdicts = None
    if candidates and cfg.verify:
        try:
            verdicts = verify_findings(candidates, chain, address, cfg.cache_dir, cfg.api_key)
            theft = confirmed_findings(verdicts)
        except Exception as exc:
            _log(cfg, f"    verification warning ({exc}); holding findings for manual review")
            theft = []  # unconfirmed -> do not claim vulnerable
    if not theft:
        extra = ""
        if candidates and (verdicts is not None):
            extra = f" ({len(candidates)} candidate(s) not confirmed by second pass)"
        store.update(chain, address, status="safe", name=name, findings=0, max_severity=None,
                     balance_wei=None if balance is None else str(balance), error=extra or None)
        return "safe"

    report = write_contract_report(chain, address, meta, theft, balance, src, cfg.out_dir, verdicts=verdicts)
    worst = min(theft, key=lambda f: SEVERITY_RANK[f.severity]).severity
    store.update(chain, address, status="vulnerable", name=name, findings=len(theft), max_severity=worst,
                 balance_wei=None if balance is None else str(balance), report=str(report), error=None)
    return "vulnerable"


def _describe(status: str, store, chain: str, address: str) -> str:
    row = store.db.execute("SELECT * FROM contracts WHERE chain=? AND address=?", (chain, address)).fetchone()
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
        for addr in rpc.created_contracts(n):
            if ADDRESS_RE.match(addr) and store.enqueue(chain, addr, f"block:{n}"):
                found += 1
                _log(cfg, f"  + block {n}: new contract {addr}")
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
