import types
import unittest

from bountyscan import chain_payload as cp
from bountyscan.chain_exploit import ChainVerdict


def _f(det, fn="withdraw"):
    return types.SimpleNamespace(detector=det, function=fn, contract="C", severity="high")


class RunChainPayloads(unittest.TestCase):
    def setUp(self):
        self._orig = cp.run_chain_poc

    def tearDown(self):
        cp.run_chain_poc = self._orig

    def test_confirmed_emits_finding_with_required_fields(self):
        cp.run_chain_poc = lambda *a, **k: ChainVerdict("reentrancy", "confirmed", "d", profit_wei=500, test_path="p.t.sol")
        out, log = cp.run_chain_payloads([_f("reentrancy")], [], "0x" + "ab" * 20, "ethereum", "rpc")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].pattern, "reentrancy")
        self.assertEqual(out[0].gain_wei, 500)
        self.assertEqual(out[0].poc_path, "p.t.sol")          # runnable with forge test --match-path
        self.assertEqual(out[0].address, "0x" + "ab" * 20)
        self.assertIn(("reentrancy", "CONFIRMED"), log)

    def test_no_profit_emits_nothing(self):
        cp.run_chain_poc = lambda *a, **k: ChainVerdict("reentrancy", "no_profit", "d")
        out, log = cp.run_chain_payloads([_f("reentrancy")], [], "0x0", "ethereum", "rpc")
        self.assertEqual(out, [])                              # the gate rejected it
        self.assertIn(("reentrancy", "DISCARDED"), log)

    def test_error_emits_nothing(self):
        cp.run_chain_poc = lambda *a, **k: ChainVerdict("reentrancy", "error", "did not compile")
        out, log = cp.run_chain_payloads([_f("reentrancy")], [], "0x0", "ethereum", "rpc")
        self.assertEqual(out, [])
        self.assertTrue(any(p == "reentrancy" and o.startswith("ERROR") for p, o in log))

    def test_none_generator_logged_not_emitted(self):
        cp.run_chain_poc = lambda *a, **k: None
        out, log = cp.run_chain_payloads([_f("donation")], [], "0x0", "ethereum", "rpc")  # donation -> amm_donation
        self.assertEqual(out, [])
        self.assertIn(("amm_donation", "no-generator"), log)

    def test_non_pattern_finding_skipped(self):
        out, log = cp.run_chain_payloads([_f("unprotected-privileged-function")], [], "0x0", "ethereum", "rpc")
        self.assertEqual(out, [])
        self.assertEqual(log, [])


if __name__ == "__main__":
    unittest.main()
