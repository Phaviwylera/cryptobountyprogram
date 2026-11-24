"""Payload-phase wiring for the chain-exploit generators.

Additive to forge_verify's single-call probe: for a finding whose detector maps to a chain pattern, run
the pattern's generator on a mainnet fork. A finding is emitted ONLY when the attacker profit assertion
passes (CONFIRMED); DISCARDED (no profit) and ERROR (compile/fork failure) emit nothing and are logged.
The profit gate is the single source of truth. This touches only the payload phase - never /live, the
dashboard, or the contract-scanning (detector / source-fetch) logic.
"""
from __future__ import annotations

import json as _json
import time
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path

from .chain_exploit import NATIVE_TOKEN, PATTERN_OF, run_chain_poc
from .forge_verify import _function_of


def _latest_block(rpc_url: str) -> int | None:
    try:
        body = _json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}).encode()
        req = urllib.request.Request(rpc_url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return int(_json.loads(r.read().decode())["result"], 16)
    except Exception:
        return None


@dataclass
class ChainFinding:
    pattern: str            # reentrancy | erc4626_inflation | amm_donation | spot_price
    chain: str
    address: str
    function: str
    gain_wei: int
    gain_usd: float         # attacker profit in USD (eth_price * gain_wei) - must clear min_gain_usd
    token: str              # token address the attacker gained (native sentinel for ETH)
    poc_path: str           # runnable: forge test --match-path <poc_path>
    report_path: str        # Immunefi-format report
    target_tvl_usd: float = 0.0   # the target's value-at-risk at scan time - must clear min_tvl_usd

    def to_dict(self) -> dict:
        return asdict(self)


def _eth_price(rpc_url: str) -> float | None:
    """USD price of ETH from on-chain Chainlink (via value.prices), or None if unavailable."""
    try:
        from .rpc import RPC
        from .value import prices
        return prices(RPC(rpc_url), 1).get("eth")
    except Exception:
        return None


def run_chain_payloads(findings, files, target: str, chain: str, rpc_url: str,
                       fork_block: int | None = None, out_dir: Path | None = None,
                       max_targets: int = 25, max_minutes: int = 30, max_pattern_matches: int = 5,
                       second_block_offset: int = 10, digest=None, health=None,
                       target_tvl_usd: float | None = None, eth_price_usd: float | None = None,
                       min_gain_usd: float = 100.0, min_tvl_usd: float = 10_000.0,
                       audit=None, target_name: str | None = None) -> tuple[list[ChainFinding], list]:
    """Run the chain generator for each pattern-matched finding against the REAL target, under a staged-
    rollout cost cap, and emit a finding ONLY after it reconfirms on a SECOND fork block AND clears an
    economically meaningful threshold.

    Caps: at most `max_targets` PoC runs and `max_minutes` wall-clock per contract; a contract matching
    more than `max_pattern_matches` patterns is skipped as a likely false-positive cluster. Chain is
    restricted to Ethereum mainnet. Every CONFIRMED PoC is re-run at `latest - second_block_offset`; a
    finding that does not reproduce there is DISCARDED (transient-state false positive).

    Economic gate: a twice-confirmed PoC is a finding ONLY when the attacker's realised profit
    `gain_usd >= min_gain_usd` ($100) AND the target's value-at-risk `target_tvl_usd >= min_tvl_usd`
    ($10k). Any profit > 0 below these is a build artifact, not a bug: it is DISCARDED and logged to the
    digest as `below_threshold`. `target_tvl_usd` is the holdings USD computed by the scan pipeline at
    scan time; `eth_price_usd` converts gain_wei (native) to USD (fetched on-chain if not supplied).
    """
    out: list[ChainFinding] = []
    log: list[tuple[str, str]] = []
    if chain != "ethereum":                           # staged rollout: Ethereum mainnet (chain id 1) only
        return out, [("_skip", "non-eth-chain")]
    pattern_findings = [f for f in findings if PATTERN_OF.get(getattr(f, "detector", ""))]
    matched_pats = sorted({PATTERN_OF[f.detector] for f in pattern_findings})
    generated_pats: set = set()
    confirmed_pats: set = set()

    def _flush_pattern_stats(ran_count: int):
        # Write-only diagnostics: per-pattern hit rate (digest) + per-target generators_run (audit).
        if digest:
            digest.record_patterns({p: {"matched": 1, "generated": 1 if p in generated_pats else 0,
                                        "confirmed": 1 if p in confirmed_pats else 0} for p in matched_pats})
        if audit:
            audit.record(target, name=target_name, generators_run=ran_count)

    if len(pattern_findings) > max_pattern_matches:   # K cap: FP cluster, skip the whole contract
        if digest:
            digest.record(target, matched=len(pattern_findings), skipped=True)
        if health:
            health.record(target=True)
        _flush_pattern_stats(0)   # matched but never generated (FP cluster)
        return out, [("_skip", f"fp-cluster:{len(pattern_findings)}>{max_pattern_matches}")]

    eth_px = eth_price_usd if eth_price_usd is not None else _eth_price(rpc_url)
    tvl = target_tvl_usd if target_tvl_usd is not None else 0.0
    latest = _latest_block(rpc_url)
    deadline = time.time() + max_minutes * 60
    ran = 0
    confirmed = 0
    discarded_2nd = 0
    below_threshold = 0
    seen = set()
    hc = {"rpc_calls": 1, "rpc_errors": 1 if latest is None else 0,
          "forge_runs": 0, "forge_timeouts": 0, "forge_errors": 0}   # health counters for this contract
    for f in pattern_findings:
        if ran >= max_targets or time.time() > deadline:
            log.append(("_cap", "budget-exhausted"))
            break
        pat = PATTERN_OF[f.detector]
        key = (pat, getattr(f, "function", ""))
        if key in seen:
            continue
        seen.add(key)
        fn = _function_of(files, f)
        try:
            v = run_chain_poc(f, fn, target, chain, rpc_url, fork_block=fork_block)
            hc["forge_runs"] += 1
        except Exception as exc:
            hc["forge_runs"] += 1
            hc["forge_errors"] += 1
            log.append((pat, f"ERROR:{exc}"[:60]))
            continue
        ran += 1
        generated_pats.add(pat)       # this pattern passed the FP-cluster gate and reached the generator
        if v is None:
            log.append((pat, "no-generator"))
            continue
        if v.outcome == "confirmed":
            # Second-block re-confirmation: a real bug reproduces at an earlier block; transient state does not.
            second = (latest - second_block_offset) if latest else None
            v2 = None
            if second:
                try:
                    v2 = run_chain_poc(f, fn, target, chain, rpc_url, fork_block=second)
                    hc["forge_runs"] += 1
                except Exception:
                    hc["forge_runs"] += 1
                    hc["forge_errors"] += 1
                    v2 = None
            if v2 is not None and v2.outcome == "confirmed":
                # Economic gate: a profit > 0 is not a finding unless it is economically meaningful AND the
                # target actually holds value. gain_wei is native (ETH) wei; price it, require >= $100 gain
                # and >= $10k target TVL. Below either -> DISCARD as a build artifact (below_threshold).
                gain_usd = (v.profit_wei / 1e18) * eth_px if eth_px else None
                gain_ok = gain_usd is not None and gain_usd >= min_gain_usd
                tvl_ok = tvl >= min_tvl_usd
                if gain_ok and tvl_ok:
                    out.append(ChainFinding(pat, chain, target, getattr(f, "function", ""), v.profit_wei,
                                            round(gain_usd, 2), NATIVE_TOKEN, v.test_path, "", round(tvl, 2)))
                    confirmed += 1
                    confirmed_pats.add(pat)
                    log.append((pat, "CONFIRMED-2x"))
                else:
                    below_threshold += 1
                    why = []
                    if not gain_ok:
                        why.append(f"gain=${(gain_usd or 0):.0f}<{min_gain_usd:.0f}")
                    if not tvl_ok:
                        why.append(f"tvl=${tvl:.0f}<{min_tvl_usd:.0f}")
                    log.append((pat, "BELOW-THRESHOLD:" + ",".join(why)))
            else:
                discarded_2nd += 1
                log.append((pat, "DISCARDED-2nd-block"))
        elif v.outcome == "no_profit":
            log.append((pat, "DISCARDED"))
        else:                                             # error: compile / fork / timeout
            if "timed out" in (v.detail or ""):
                hc["forge_timeouts"] += 1
            else:
                hc["forge_errors"] += 1
            log.append((pat, f"ERROR:{v.detail}"[:60]))
    if digest:
        digest.record(target, matched=len(pattern_findings), ran=ran, confirmed=confirmed,
                      discarded_2nd=discarded_2nd, below_threshold=below_threshold,
                      confirmed_usd=sum(h.gain_usd for h in out))
    if health:
        health.record(target=True, finding=(confirmed > 0), **hc)
    _flush_pattern_stats(ran)
    return out, log


# ---------------------------------------------------------------------------------------------
# Integration self-test: feed the four CONTROLLED targets (vulnerable + safe) through the full
# generator -> fork -> profit-gate path and build a findings feed, exactly as the payload phase would.
_PATTERN_RUNNERS = ("reentrancy", "erc4626_inflation", "amm_donation", "spot_price")


def selftest_feed(rpc_url: str, out_dir: Path) -> tuple[list[ChainFinding], list[str]]:
    """Run the 4 pattern self-tests (each deploys a controlled vulnerable + safe target). Returns
    (vuln_findings, safe_failures): vuln_findings is the emitted feed (should be 4, one per pattern, all
    gain>0); safe_failures lists any pattern whose SAFE target was NOT discarded (should be empty)."""
    from . import chain_selftest as st
    runners = [("reentrancy", st.run_self_test),
               ("erc4626_inflation", st.run_erc4626_self_test),
               ("amm_donation", st.run_amm_self_test),
               ("spot_price", st.run_spot_self_test)]
    vuln: list[ChainFinding] = []
    safe_failures: list[str] = []
    for pat, runner in runners:
        res = runner(rpc_url, Path(out_dir))
        gain = res.get("vuln_profit_wei")
        if gain is None:                               # run_self_test returns nested vuln dict
            gain = (res.get("vuln") or {}).get("profit_wei", 0)
        if res.get("vuln_confirmed") and gain and gain > 0:
            vuln.append(ChainFinding(pat, "fork", "(controlled target)", "withdraw", int(gain), 0.0,
                                     NATIVE_TOKEN, "", res.get("report_path", "")))
        if not res.get("safe_discarded"):              # a safe target that confirmed = integration failure
            safe_failures.append(pat)
    return vuln, safe_failures


def run_integration_selftest(rpc_url: str, out_dir: Path) -> dict:
    """The integration assertion: 4 confirmed findings from the vulnerable targets (all gain>0), and 0
    safe targets that failed to discard. Returns a dict with the pass/fail and the feed."""
    vuln, safe_failures = selftest_feed(rpc_url, out_dir)
    patterns = sorted({f.pattern for f in vuln})
    ok = (len(vuln) == 4 and all(f.gain_wei > 0 for f in vuln)
          and len(patterns) == 4 and len(safe_failures) == 0)
    return {"integration_green": ok, "vuln_findings": len(vuln), "patterns": patterns,
            "all_gain_positive": all(f.gain_wei > 0 for f in vuln) if vuln else False,
            "safe_failures": safe_failures, "feed": [f.to_dict() for f in vuln]}
