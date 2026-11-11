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
