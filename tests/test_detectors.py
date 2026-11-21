import json
import tempfile
import unittest
from pathlib import Path

from bountyscan.cli import main
from bountyscan.report import write_all
from bountyscan.scanner import scan
from bountyscan.solidity import parse_source
from bountyscan.sources import _safe_relpath

FIXTURES = Path(__file__).parent / "fixtures"


def hits(findings, detector):
    return [f for f in findings if f.detector == detector]


class SenderAdmissionGuard(unittest.TestCase):
    """Phase-2 CFG: the multi-principal inline guard `if (msg.sender == owner || msg.sender == dev)`."""

    def test_or_of_senders_is_a_guard(self):
        from bountyscan.detectors import sender_admission_guard
        self.assertTrue(sender_admission_guard("if (msg.sender == owner || msg.sender == dev) { x = _c; }"))
        self.assertTrue(sender_admission_guard("if (msg.sender == owner) { x = _c; }"))
        self.assertTrue(sender_admission_guard("if (paused == false && msg.sender == owner) { x = _c; }"))

    def test_mixed_or_admitting_nonsender_is_not_a_guard(self):
        from bountyscan.detectors import sender_admission_guard
        # a disjunct that admits a public path (timestamp / bool) must NOT be mistaken for access control
        self.assertFalse(sender_admission_guard("if (block.timestamp > start || msg.sender == owner) { x = _c; }"))
        self.assertFalse(sender_admission_guard("if (isPublic || msg.sender == owner) { x = _c; }"))
        self.assertFalse(sender_admission_guard("x = _c;"))


class InitStateGuard(unittest.TestCase):
    """Phase-4 CFG: set-once initialization guards (not re-callable on a live contract)."""

    def test_setonce_guards_recognised(self):
        from bountyscan.detectors import init_guarded
        from types import SimpleNamespace as NS
        for body in ("require(!initialized); initialized = true; controller = c;",
                     "require(_initialized == false); x = c;",
                     "require(slot0.sqrtPriceX96 == 0); init();",
                     "if (initialized) revert AlreadyInit(); initialized = true;"):
            self.assertTrue(init_guarded(NS(body=body)), body)

    def test_reentrancy_lock_is_not_an_init_guard(self):
        from bountyscan.detectors import init_guarded
        from types import SimpleNamespace as NS
        # a per-tx reentrancy lock does NOT make an unprotected privileged setter safe
        self.assertFalse(init_guarded(NS(body="require(!locked); locked = true; controller = c;")))
        self.assertFalse(init_guarded(NS(body="controller = c;")))


class ParserTests(unittest.TestCase):
    def test_parses_contracts_functions_and_state(self):
        sf = parse_source(FIXTURES / "vulnerable" / "VulnerableVault.sol")
        vault = next(c for c in sf.contracts if c.name == "VulnerableVault")
        self.assertIn("withdrawEth", [f.name for f in vault.functions])
        self.assertTrue({"ethDeposits", "totalSupply", "owner", "implementation"} <= vault.state_vars)
        execute = vault.function("execute")
        self.assertEqual(execute.visibility, "external")
        self.assertEqual(execute.mutability, "payable")
        self.assertEqual([p.name for p in execute.params], ["target", "data"])

    def test_comments_do_not_shift_lines(self):
        sf = parse_source(FIXTURES / "vulnerable" / "VulnerableVault.sol")
        fn = next(c for c in sf.contracts if c.name == "VulnerableVault").function("withdrawEth")
        self.assertIn("function withdrawEth", sf.line_text(sf.line_of(fn.offset)))

    def test_safe_relpath_blocks_traversal(self):
        self.assertEqual(_safe_relpath("../../etc/passwd"), Path("etc/passwd"))
        self.assertEqual(_safe_relpath("/abs/x.sol"), Path("abs/x.sol"))
        self.assertEqual(_safe_relpath("C:\\win\\x.sol"), Path("win/x.sol"))


class VulnerableFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = scan([FIXTURES / "vulnerable"], min_severity="info").findings

    def assertDetected(self, detector, function=None):
        found = hits(self.findings, detector)
        if function:
            found = [f for f in found if f.function == function]
        self.assertTrue(found, f"{detector} not reported{' in ' + function if function else ''}")
        return found

    def test_fund_theft_classes(self):
        self.assertDetected("reentrancy", "withdrawEth")
        self.assertDetected("unprotected-initializer", "initialize")
        self.assertDetected("arbitrary-recipient-withdrawal", "withdrawTo")
        self.assertDetected("unprotected-privileged-function", "setImplementation")
        self.assertDetected("unrestricted-mint", "mint")
        self.assertDetected("arbitrary-external-call", "execute")
        self.assertDetected("controlled-delegatecall", "upgradeAndCall")
        self.assertDetected("tx-origin-auth", "upgradeAndCall")
        self.assertDetected("unprotected-selfdestruct", "kill")
        self.assertDetected("unvalidated-flash-callback", "onFlashLoan")
        self.assertDetected("unvalidated-flash-callback", "pancakeCall")
        self.assertDetected("arbitrary-transferfrom", "pull")
        self.assertDetected("arbitrary-approval", "allow")
        self.assertDetected("unprotected-privileged-function", "rescueNative")  # pays a caller-chosen address
        self.assertDetected("unprotected-privileged-function", "recover")       # PaymentHub (real finding)
        self.assertDetected("unprotected-privileged-function", "setPrice")      # caller-supplied price
        self.assertDetected("unprotected-privileged-function", "setStakingToken")  # CellarStaking (real)
        self.assertDetected("arbitrary-transferfrom", "depositNFT")                # BitStake (real)
        self.assertDetected("cross-function-reentrancy", "borrow")
        self.assertDetected("reentrancy", "withdraw")  # state write in internal helper

    def test_defi_economic_classes(self):
        self.assertDetected("erc4626-inflation", "deposit")
        self.assertDetected("donation-manipulable-rate", "deposit")
        self.assertDetected("spot-price-oracle", "collateralPrice")
        self.assertDetected("chainlink-stale-price", "feedPrice")
        self.assertDetected("missing-slippage-protection", "harvest")
        self.assertDetected("signature-replay", "withdrawWithSig")

    def test_hygiene_classes(self):
        self.assertDetected("unchecked-erc20-transfer", "deposit")
        self.assertDetected("unchecked-low-level-call", "sendFee")
        self.assertDetected("weak-randomness", "lottery")
        self.assertDetected("divide-before-multiply", "interest")
        self.assertDetected("pre-0.8-overflow", "batchTransfer")

    def test_severity_assignment(self):
        self.assertEqual(self.assertDetected("arbitrary-external-call")[0].severity, "critical")
        self.assertEqual(self.assertDetected("reentrancy")[0].severity, "high")
        sev = {f.severity for f in hits(self.findings, "unprotected-privileged-function")}
        self.assertIn("critical", sev)

    def test_findings_sorted_by_severity(self):
        ranks = ["critical", "high", "medium", "low", "info"]
        order = [ranks.index(f.severity) for f in self.findings]
        self.assertEqual(order, sorted(order))


class SafeFixtureTests(unittest.TestCase):
    def test_no_findings_on_hardened_vault(self):
        findings = scan([FIXTURES / "safe"], min_severity="info").findings
        self.assertEqual([], [(f.detector, f.function, f.line) for f in findings],
                         "hardened fixtures must stay clean (incl. ERC1363 transferAndCall / verified uniswapV2Call)")


class PrecisionSuppressionTests(unittest.TestCase):
    """The three FP classes confirmed on live contracts are suppressed, while the REAL shape each one
    mimics still fires (no true positive lost). Each test scopes its assertion to one detector so
    unrelated detectors don't interfere."""

    def _dets(self, src: str):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "C.sol").write_text(src, encoding="utf-8")
            return {f.detector for f in scan([Path(tmp)], min_severity="info").findings}

    def test_proof_gated_relay_not_flagged_but_open_forwarder_is(self):
        gated = """pragma solidity ^0.8.20;
contract Bridge {
    bytes32 public root;
    function relayMsgWithProof(address target, bytes calldata data, bytes calldata proof) external {
        require(verifyMerkleProof(root, keccak256(data), proof), "Invalid proof");
        (bool ok,) = target.call(data);
        require(ok, "RelayMsg Failed");
    }
    function verifyMerkleProof(bytes32 r, bytes32 l, bytes calldata p) internal pure returns (bool) { return p.length > 0; }
}"""
        self.assertNotIn("arbitrary-external-call", self._dets(gated))      # merkle-gated bridge relay (L1Mailbox/Wormhole shape)
        open_fwd = """pragma solidity ^0.8.20;
contract Router {
    function execute(address target, bytes calldata data) external {
        (bool ok,) = target.call(data); require(ok);
    }
}"""
        self.assertIn("arbitrary-external-call", self._dets(open_fwd))       # the real LiFi/Socket open forwarder still fires

    def test_token_own_transferfrom_not_flagged_but_router_is(self):
        token = """pragma solidity ^0.8.20;
contract MyToken is ERC20Upgradeable {
    function transferFromWithUpdatePrice(address from, address to, uint256 v, bytes[] calldata u) public returns (bool) {
        return super.transferFrom(from, to, v);
    }
}"""
        self.assertNotIn("arbitrary-transferfrom", self._dets(token))        # token's own allowance-spending transferFrom (Cashiva shape)
        router = """pragma solidity ^0.8.20;
interface IERC20 { function transferFrom(address,address,uint256) external returns (bool); }
contract Router {
    function pull(address token, address from, address to, uint256 v) external {
        IERC20(token).transferFrom(from, to, v);
    }
}"""
        self.assertIn("arbitrary-transferfrom", self._dets(router))          # the real approved-spender drain still fires

    def test_safeerc20_library_form_reads_from_at_arg1(self):
        # SafeERC20.safeTransferFrom(IERC20(token), msg.sender, to, amt): `from` is arg1 (msg.sender), not
        # arg0 (the token param) - the Wormhole _transferTokens shape. Must NOT be flagged.
        wormhole = """pragma solidity ^0.8.20;
library SafeERC20 { function safeTransferFrom(IERC20 t, address f, address to, uint256 v) internal {} }
interface IERC20 {}
contract Bridge {
    function transferTokens(address token, uint256 amount) external {
        SafeERC20.safeTransferFrom(IERC20(token), msg.sender, address(this), amount);
    }
}"""
        self.assertNotIn("arbitrary-transferfrom", self._dets(wormhole))
        # but the library form with a caller-chosen victim as `from` (arg1) IS still a real drain
        drain = """pragma solidity ^0.8.20;
library SafeERC20 { function safeTransferFrom(IERC20 t, address f, address to, uint256 v) internal {} }
interface IERC20 {}
contract Router {
    function pull(address token, address victim, uint256 amount) external {
        SafeERC20.safeTransferFrom(IERC20(token), victim, msg.sender, amount);
    }
}"""
        self.assertIn("arbitrary-transferfrom", self._dets(drain))

    def test_governance_vaa_gated_upgrade_not_flagged_but_open_upgrade_is(self):
        gated = """pragma solidity ^0.8.20;
contract BridgeGovernance {
    function upgrade(bytes memory encodedVM) public {
        (address impl, bool valid,) = verifyGovernanceVM(encodedVM);
        require(valid, "invalid VAA");
        _upgradeTo(impl);
    }
    function verifyGovernanceVM(bytes memory vm) internal returns (address, bool, string memory) { return (address(0), vm.length>0, ""); }
    function _upgradeTo(address a) internal {}
}"""
        self.assertNotIn("unprotected-privileged-function", self._dets(gated))
        open_up = """pragma solidity ^0.8.20;
contract C {
    address public implementation;
    function upgrade(address newImpl) public { implementation = newImpl; }
}"""
        self.assertIn("unprotected-privileged-function", self._dets(open_up))

    def test_parent_name_delegation_is_access_controlled(self):
        # transferOwnership override forwarding to Ownable2StepUpgradeable.transferOwnership (onlyOwner parent).
        src = """pragma solidity ^0.8.20;
contract StakingVault is Ownable2StepUpgradeable {
    function transferOwnership(address _newOwner) public override {
        Ownable2StepUpgradeable.transferOwnership(_newOwner);
    }
}"""
        self.assertNotIn("unprotected-privileged-function", self._dets(src))

    def test_cross_function_reentrancy_skips_role_gated_other(self):
        src = """pragma solidity ^0.8.20;
contract Mailbox {
    mapping(address => uint256) public feeBalance;
    address public withdrawer;
    modifier onlyWithdrawer() { require(msg.sender == withdrawer, "Only callable by the withdrawer"); _; }
    function sendMsg(address target, uint256 v) external {
        (bool ok,) = target.call{value: v}("");
        require(ok);
        feeBalance[msg.sender] -= v;
    }
    function withdrawDepositFee(address to, uint256 v) external onlyWithdrawer {
        feeBalance[address(this)] -= v;
        payable(to).transfer(v);
    }
}"""
        self.assertNotIn("cross-function-reentrancy", self._dets(src))       # the only shared-state mutator is withdrawer-only


class ReportAndCliTests(unittest.TestCase):
    def test_reports_written(self):
        result = scan([FIXTURES / "vulnerable"])
        with tempfile.TemporaryDirectory() as tmp:
            program = {"program": "Demo", "submission_url": "https://immunefi.com/bug-bounty/demo/"}
            paths = write_all(result, Path(tmp), {"md", "json", "sarif", "drafts"}, program)
            names = {p.name for p in paths}
            self.assertTrue({"report.md", "findings.json", "results.sarif"} <= names)
            data = json.loads((Path(tmp) / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(len(data["findings"]), len(result.findings))
            sarif = json.loads((Path(tmp) / "results.sarif").read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            drafts = list((Path(tmp) / "submissions").glob("*.md"))
            self.assertTrue(drafts)
            self.assertIn("https://immunefi.com/bug-bounty/demo/", drafts[0].read_text(encoding="utf-8"))

    def test_cli_fail_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = main(["scan", str(FIXTURES / "vulnerable"), "--out", tmp, "--format", "json", "--fail-on", "critical"])
            self.assertEqual(rc, 1)
            rc = main(["scan", str(FIXTURES / "safe"), "--out", tmp, "--format", "json", "--fail-on", "low"])
            self.assertEqual(rc, 0)

    def test_program_scope_with_local_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scope.json"
            scope.write_text(json.dumps({
                "program": "Demo", "platform": "immunefi",
                "submission_url": "https://immunefi.com/bug-bounty/demo/",
                "assets": [{"name": "vault", "path": str((FIXTURES / "vulnerable").resolve())}],
            }), encoding="utf-8")
            rc = main(["program", str(scope), "--out", str(Path(tmp) / "r"), "--format", "md", "--fail-on", "critical"])
            self.assertEqual(rc, 1)
            report = next((Path(tmp) / "r").glob("Demo-*/report.md")).read_text(encoding="utf-8")
            self.assertIn("Submit verified findings at", report)


if __name__ == "__main__":
    unittest.main()
