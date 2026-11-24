import json
import tempfile
import types
import unittest
from pathlib import Path

from bountyscan import chain_payload as cp
from bountyscan.chain_digest import Digest
from bountyscan.chain_exploit import ChainVerdict


def _f(det, fn="withdraw"):
    return types.SimpleNamespace(detector=det, function=fn, contract="C", severity="high")


class RunChainPayloads(unittest.TestCase):
    def setUp(self):
        self._poc = cp.run_chain_poc
        self._blk = cp._latest_block
        cp._latest_block = lambda rpc: 1_000_000          # no network

    def tearDown(self):
        cp.run_chain_poc = self._poc
        cp._latest_block = self._blk

    def test_confirmed_requires_second_block_reconfirm(self):
        cp.run_chain_poc = lambda *a, **k: ChainVerdict("reentrancy", "confirmed", "d", profit_wei=500, test_path="p.t.sol")
        out, log = cp.run_chain_payloads([_f("reentrancy")], [], "0x" + "ab" * 20, "ethereum", "rpc")
        self.assertEqual(len(out), 1)                     # confirmed on BOTH blocks
        self.assertEqual(out[0].gain_wei, 500)
        self.assertIn(("reentrancy", "CONFIRMED-2x"), log)

    def test_second_block_discard(self):
        calls = {"n": 0}
        def poc(*a, **k):
            calls["n"] += 1
            return ChainVerdict("reentrancy", "confirmed" if calls["n"] == 1 else "no_profit", "d", profit_wei=500)
        cp.run_chain_poc = poc
        out, log = cp.run_chain_payloads([_f("reentrancy")], [], "0x0", "ethereum", "rpc")
        self.assertEqual(out, [])                         # failed to reproduce on the 2nd block -> discarded
        self.assertIn(("reentrancy", "DISCARDED-2nd-block"), log)

    def test_fp_cluster_skipped(self):
        many = [_f("reentrancy", f"f{i}") for i in range(3)] + [_f("donation", "d"), _f("spot-price-oracle", "s"),
                _f("erc4626-inflation", "e"), _f("unvalidated-flash-callback", "c")]  # 7 pattern matches > 5
        out, log = cp.run_chain_payloads(many, [], "0x0", "ethereum", "rpc", max_pattern_matches=5)
        self.assertEqual(out, [])
        self.assertTrue(any(k == "_skip" and o.startswith("fp-cluster") for k, o in log))

    def test_non_ethereum_chain_skipped(self):
        cp.run_chain_poc = lambda *a, **k: ChainVerdict("reentrancy", "confirmed", "d", profit_wei=1)
        out, log = cp.run_chain_payloads([_f("reentrancy")], [], "0x0", "base", "rpc")
        self.assertEqual(out, [])
        self.assertEqual(log, [("_skip", "non-eth-chain")])

    def test_max_targets_cap(self):
        cp.run_chain_poc = lambda *a, **k: ChainVerdict("reentrancy", "no_profit", "d")
        fs = [_f("reentrancy", f"fn{i}") for i in range(10)]
        out, log = cp.run_chain_payloads(fs, [], "0x0", "ethereum", "rpc", max_targets=3, max_pattern_matches=100)
        self.assertEqual(out, [])
        self.assertIn(("_cap", "budget-exhausted"), log)

    def test_no_profit_emits_nothing(self):
        cp.run_chain_poc = lambda *a, **k: ChainVerdict("reentrancy", "no_profit", "d")
        out, log = cp.run_chain_payloads([_f("reentrancy")], [], "0x0", "ethereum", "rpc")
        self.assertEqual(out, [])
        self.assertIn(("reentrancy", "DISCARDED"), log)

    def test_non_pattern_finding_skipped(self):
        out, log = cp.run_chain_payloads([_f("unprotected-privileged-function")], [], "0x0", "ethereum", "rpc")
        self.assertEqual(out, [])
        self.assertEqual(log, [])


class DigestTest(unittest.TestCase):
    def test_accumulates_and_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Digest(tmp)
            d.record("0xaaa", matched=2, ran=2, confirmed=1, discarded_2nd=1, confirmed_usd=10338.0)
            d.record("0xbbb", matched=5, skipped=True)
            files = list(Path(tmp).glob("*.json"))
            self.assertEqual(len(files), 1)
            j = json.loads(files[0].read_text())
            self.assertEqual(j["targets_scanned"], 2)
            self.assertEqual(j["confirmed"], 1)
            self.assertEqual(j["discarded_second_block"], 1)
            self.assertEqual(j["skipped_fp_clusters"], 1)
            self.assertEqual(j["confirmed_usd"], 10338.0)
            self.assertEqual(j["confirmed_targets"], ["0xaaa"])


if __name__ == "__main__":
    unittest.main()
