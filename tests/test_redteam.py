"""Regression gate: an adversarial corpus of exploit-modelled contracts (The DAO, Fei Rari, Cream, LiFi,
Socket, DODO, Balancer, Uniswap V2/V3/V4 callbacks, ...) and their hardened counterparts.

Every vulnerable contract must be flagged and no safe contract may be. The server's auto-deploy runs the
test suite before switching versions, so a change that weakens detection is rolled back automatically.
"""
import unittest
from pathlib import Path

from bountyscan.scanner import scan

CORPUS = Path(__file__).parent / "fixtures" / "redteam"


class RedTeamCorpus(unittest.TestCase):
    def test_every_exploit_is_caught(self):
        files = sorted((CORPUS / "vulnerable").glob("*.sol"))
        self.assertGreaterEqual(len(files), 25)
        flagged = {Path(f.file).name for f in scan([CORPUS / "vulnerable"], min_severity="medium").findings}
        missed = [p.name for p in files if p.name not in flagged]
        self.assertEqual(missed, [], f"exploit patterns no longer detected: {missed}")

    def test_no_false_positive_on_hardened_versions(self):
        findings = scan([CORPUS / "safe"], min_severity="medium").findings
        self.assertEqual([(Path(f.file).name, f.detector, f.function) for f in findings], [])


if __name__ == "__main__":
    unittest.main()
