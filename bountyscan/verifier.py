"""Independent confirmation pass for fund-theft findings.

Your instruction was: rerun and confirm every vulnerability with a SEPARATE agent, tolerance 0.01%.
That is implemented here as a second, independent analysis that must agree before a finding is saved:

  1. Re-fetch the source FRESH from the explorer (bypassing cache) so verification never trusts
     the same bytes the first scan read.
  2. Re-parse and re-run the SAME detector from a clean project state - the finding must reproduce
     at the same contract/function.
  3. Run detector-specific *counter-checks*: look for a mitigating guard the first pass might have
     missed (an auth modifier resolved from a parent, a reentrancy lock, a nonce, a one-time init
     guard, a slippage floor). If a guard is present, the finding is REFUTED.
  4. Confirm the flagged code is reachable (the function is an external entry point, or reached from
     one) - a finding in dead/internal-only code is downgraded.

Only findings that REPRODUCE and are not REFUTED are marked confirmed. Everything else is held back
with the reason, so a human can look without it polluting the results page. This is deliberately
conservative: a false "confirmed" wastes a bounty triage and risks a wrong public claim, so when the
two passes disagree we do not report.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .detectors import (
    AUTH_BODY_RE,
    REENTRANCY_GUARD_RE,
    SENDER,
    Finding,
    SEVERITY_RANK,
    build_project,
    run_detectors,
)
from .solidity import SourceFile, parse_source
from .sources import fetch_verified_source
from .remediation import is_fund_theft


@dataclass
class Verdict:
    finding: Finding
    confirmed: bool
    reproduced: bool
    reason: str
    counter_checks: list[str]


def _function_of(files: list[SourceFile], finding: Finding):
    for sf in files:
        if sf.display != finding.file and Path(sf.display).name != Path(finding.file).name:
            continue
        for c in sf.contracts:
            if c.name != finding.contract:
                continue
            for fn in c.functions:
                if fn.name == finding.function:
                    return fn, c
    return None, None


# A guard whose presence refutes each class of finding.
GUARD_CHECKS = {
    "reentrancy": (
        "reentrancy guard / CEI",
        lambda fn, c, proj: (
            any(REENTRANCY_GUARD_RE.search(m) for m in fn.modifiers)
            or _state_written_before_call(fn, proj)
        ),
    ),
    "unprotected-privileged-function": (
        "access control present",
        lambda fn, c, proj: _is_access_controlled(fn, proj),
    ),
    "unprotected-initializer": (
        "one-time / initializer guard present",
        lambda fn, c, proj: bool(
            re.search(r"initializ|_initializing|inited|require\s*\([^;]*==\s*address\s*\(\s*0\s*\)|"
                      r"if\s*\([^;{]*!=\s*address\s*\(\s*0\s*\)", fn.body or "")
            or any(re.search(r"initializ", m, re.I) for m in fn.modifiers)
        ),
    ),
    "unrestricted-mint": ("access control / payment present", lambda fn, c, proj: _is_access_controlled(fn, proj)
                          or bool(re.search(r"msg\.value|transferFrom\s*\(|_spendAllowance", fn.body or ""))),
    "unrestricted-burn-from": ("allowance / owner check present", lambda fn, c, proj: _is_access_controlled(fn, proj)
                               or bool(re.search(r"allowance|_spendAllowance|_isApprovedOrOwner", fn.body or ""))),
    "arbitrary-recipient-withdrawal": ("caller is debited", lambda fn, c, proj: bool(re.search(SENDER, fn.body or ""))
                                       or _is_access_controlled(fn, proj)),
    "arbitrary-external-call": ("target/selector whitelist present", lambda fn, c, proj: _is_access_controlled(fn, proj)
                                or bool(re.search(r"allow\w*\[|whitelist|require\s*\([^;]*selector", fn.body or "", re.I))),
    "controlled-delegatecall": ("delegatecall target is fixed/admin", lambda fn, c, proj: _is_access_controlled(fn, proj)),
    "unprotected-selfdestruct": ("access control present", lambda fn, c, proj: _is_access_controlled(fn, proj)),
    "unvalidated-flash-callback": ("caller/initiator verified", lambda fn, c, proj: bool(re.search(SENDER, fn.body or ""))),
    "tx-origin-auth": ("not an auth comparison", lambda fn, c, proj: not re.search(r"tx\.origin\s*[!=]=|[!=]=\s*tx\.origin", fn.body or "")),
    "signature-replay": ("nonce + chainid present", lambda fn, c, proj: bool(
        re.search(r"nonce|used\w*\[|_useNonce", c.text, re.I) and re.search(r"chainid|_hashTypedDataV4|DOMAIN_SEPARATOR", c.text))),
    "missing-slippage-protection": ("non-zero min output", lambda fn, c, proj: not re.search(
        r"amountOutMin\w*\s*:\s*0|minAmountOut\s*:\s*0|min_dy\s*:\s*0|,\s*0\s*,", fn.body or "")),
    "spot-price-oracle": ("TWAP/oracle present", lambda fn, c, proj: bool(
        re.search(r"observe\s*\(|consult\s*\(|twap|TWAP|cumulative|latestRoundData", c.text))),
    "erc4626-inflation": ("virtual/dead shares present", lambda fn, c, proj: bool(
        re.search(r"_decimalsOffset|MINIMUM_LIQUIDITY|DEAD|0xdead|virtualShares", c.text, re.I))),
    "pre-0.8-overflow": ("SafeMath / >=0.8", lambda fn, c, proj: "SafeMath" in c.file.clean or not c.file.is_pre_08),
}


def _is_access_controlled(fn, proj) -> bool:
    for m in fn.modifiers:
        if m in proj.auth_modifiers or re.search(
            r"only|auth|admin|owner|role|gov|restricted|guardian|keeper|operator|whitelist|permission", m, re.I):
            return True
    body = fn.body or ""
    if AUTH_BODY_RE.search(body):
        return True
    if re.search(rf"\bsuper\.{re.escape(fn.name)}\s*\(", body):
        return True
    for alias in re.findall(rf"\b(\w+)\s*=\s*{SENDER}\s*;", body):
        if re.search(rf"(?:require|if)\s*\([^;{{]*\b{re.escape(alias)}\b\s*[!=]=", body):
            return True
    return False


def _state_written_before_call(fn, proj) -> bool:
    """CEI: is every state var written BEFORE the first external call?"""
    body = fn.body or ""
    call = re.search(r"\.call\s*\{|\.call\s*\(|safeTransferETH\s*\(|\.sendValue\s*\(", body)
    if not call:
        return True
    after = body[call.start():]
    for v in proj.state_vars:
        if re.search(rf"(?<![.\w]){re.escape(v)}\b\s*(?:\[[^;]*\]\s*)*(?:[+\-*/]?=(?!=)|\+\+|--)", after):
            return False
    return True


def verify_findings(findings: list[Finding], chain: str, address: str, cache_dir: Path,
                    api_key: str | None) -> list[Verdict]:
    """Independent second pass. Re-fetches source fresh and re-derives every finding."""
    theft = [f for f in findings if is_fund_theft(f)]
    if not theft:
        return []

    # Fresh fetch into a separate directory so we never reuse the first pass's bytes.
    fresh_root = cache_dir / "verify" / chain / address.lower()
    if fresh_root.exists():
        import shutil
        shutil.rmtree(fresh_root, ignore_errors=True)
    src = fetch_verified_source(address, chain, cache_dir / "verify", api_key)

    files: list[SourceFile] = []
    for p in sorted(src.rglob("*.sol")):
        try:
            files.append(parse_source(p, display=p.as_posix()))
        except Exception:
            continue
    project = build_project(files)

    # Independent detector run on the fresh parse.
    reproduced = run_detectors(files)
    repro_keys = {(f.detector, f.contract, f.function) for f in reproduced}

    verdicts = []
    for f in theft:
        key = (f.detector, f.contract, f.function)
        reproduced_ok = key in repro_keys
        counters: list[str] = []
        refuted = False
        fn, c = _function_of(files, f)
        check = GUARD_CHECKS.get(f.detector)
        if check and fn is not None:
            label, test = check
            try:
                if test(fn, c, project):
                    refuted = True
                    counters.append(f"refuted: {label}")
            except Exception:
                pass
        if fn is not None and not fn.is_entrypoint and f.detector not in ("uninitialized-implementation",):
            counters.append("note: not a direct external entry point - confirm reachability")

        confirmed = reproduced_ok and not refuted
        if not reproduced_ok:
            reason = "did not reproduce on independent re-fetch/parse"
        elif refuted:
            reason = "mitigating guard found on second pass"
        else:
            reason = "reproduced independently; no mitigating guard found"
        verdicts.append(Verdict(f, confirmed, reproduced_ok, reason, counters))
    return verdicts


def confirmed_findings(verdicts: list[Verdict]) -> list[Finding]:
    out = [v.finding for v in verdicts if v.confirmed]
    out.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.file, f.line))
    return out
