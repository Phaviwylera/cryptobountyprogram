"""Payload-phase wiring for the chain-exploit generators.

Additive to forge_verify's single-call probe: for a finding whose detector maps to a chain pattern, run
the pattern's generator on a mainnet fork. A finding is emitted ONLY when the attacker profit assertion
passes (CONFIRMED); DISCARDED (no profit) and ERROR (compile/fork failure) emit nothing and are logged.
The profit gate is the single source of truth. This touches only the payload phase - never /live, the
dashboard, or the contract-scanning (detector / source-fetch) logic.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path

from .chain_exploit import NATIVE_TOKEN, PATTERN_OF, run_chain_poc
from .forge_verify import _function_of


@dataclass
class ChainFinding:
    pattern: str            # reentrancy | erc4626_inflation | amm_donation | spot_price
    chain: str
    address: str
    function: str
    gain_wei: int
    gain_usd: float
    token: str              # token address the attacker gained (native sentinel for ETH)
    poc_path: str           # runnable: forge test --match-path <poc_path>
    report_path: str        # Immunefi-format report

    def to_dict(self) -> dict:
        return asdict(self)


def run_chain_payloads(findings, files, target: str, chain: str, rpc_url: str,
                       fork_block: int | None = None, out_dir: Path | None = None) -> tuple[list[ChainFinding], list]:
    """Run the chain generator for each pattern-matched finding against the REAL target. Returns
    (confirmed_findings, log). confirmed_findings carry a passing PoC; the log records every pattern's
    outcome (CONFIRMED / DISCARDED / ERROR / no-generator) for observability."""
    out: list[ChainFinding] = []
    log: list[tuple[str, str]] = []
    seen = set()
    for f in findings:
        pat = PATTERN_OF.get(getattr(f, "detector", ""))
        if pat is None:
            continue
        key = (pat, getattr(f, "function", ""))
        if key in seen:
            continue
        seen.add(key)
        fn = _function_of(files, f)
        try:
            v = run_chain_poc(f, fn, target, chain, rpc_url, fork_block=fork_block)
        except Exception as exc:                      # never let a PoC run break the payload phase
            log.append((pat, f"ERROR:{exc}"[:60]))
            continue
        if v is None:
            log.append((pat, "no-generator"))         # pattern recognised but no real-target template yet
            continue
        if v.outcome == "confirmed":
            out.append(ChainFinding(pat, chain, target, getattr(f, "function", ""), v.profit_wei, 0.0,
                                    NATIVE_TOKEN, v.test_path, v.test_path and ""))
            log.append((pat, "CONFIRMED"))
        elif v.outcome == "no_profit":
            log.append((pat, "DISCARDED"))            # the gate rejected it - emit nothing
        else:
            log.append((pat, f"ERROR:{v.detail}"[:60]))
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
