import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bountyscan import auto
from bountyscan.auto import AutoConfig, parse_address_lines, run_queue
from bountyscan.sources import NotVerified
from bountyscan.state import Store

FIXTURES = Path(__file__).parent / "fixtures"
VULN = "0x" + "11" * 20
SAFE = "0x" + "22" * 20
PENDING = "0x" + "33" * 20


def fake_fetch(address, chain, dest, api_key=None):
    """Stand-in for the explorer: map test addresses to fixture folders."""
    folder = {VULN: "vulnerable", SAFE: "safe"}.get(address.lower())
    if folder is None:
        raise NotVerified(address)
    out = Path(dest) / folder
    if not out.exists():
        import shutil
        shutil.copytree(FIXTURES / folder, out)
        (out / "bountyscan-meta.json").write_text(json.dumps({"contract_name": folder.title()}), encoding="utf-8")
    return out


class AutoModeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = Store(root / "state.db")
        self.cfg = AutoConfig(out_dir=root / "out", cache_dir=root / "cache", quiet=True, retry_base=0, verify=False)

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def test_parse_address_lines(self):
        text = f"# comment\n{VULN}\nbase:{SAFE}  # inline\n\narbitrum,{PENDING}\n"
        self.assertEqual(parse_address_lines(text, "ethereum"),
                         [("ethereum", VULN), ("base", SAFE), ("arbitrum", PENDING)])
        with self.assertRaises(ValueError):
            parse_address_lines("not-an-address", "ethereum")

    def test_marks_safe_and_vulnerable_and_moves_on(self):
        for a in (VULN, SAFE, PENDING):
            self.assertTrue(self.store.enqueue("ethereum", a, "test"))
        self.assertFalse(self.store.enqueue("ethereum", VULN, "dup"))  # deduplicated

        with mock.patch.object(auto, "fetch_verified_source", fake_fetch):
            tally = run_queue(self.store, self.cfg)

        self.assertEqual(tally, {"vulnerable": 1, "safe": 1, "unverified": 1})
        vuln = self.store.by_status("vulnerable")[0]
        self.assertEqual(vuln["address"], VULN)
        self.assertEqual(vuln["max_severity"], "critical")

        report = Path(vuln["report"]).read_text(encoding="utf-8")
        for section in ("### What's wrong", "### How it can be exploited", "### How to fix it", "VULNERABLE"):
            self.assertIn(section, report)
        data = json.loads((Path(vuln["report"]).parent / "findings.json").read_text(encoding="utf-8"))
        self.assertTrue(all(f["severity"] in ("critical", "high") for f in data["findings"]))

        summary = (self.cfg.out_dir / "SUMMARY.md").read_text(encoding="utf-8")
        self.assertIn(VULN, summary)
        self.assertIn(SAFE, (self.cfg.out_dir / "safe.txt").read_text(encoding="utf-8"))

    def test_scanned_contracts_are_not_rescanned(self):
        self.store.enqueue("ethereum", SAFE, "test")
        with mock.patch.object(auto, "fetch_verified_source", fake_fetch):
            run_queue(self.store, self.cfg)
            self.assertEqual(run_queue(self.store, self.cfg), {})

    def test_identical_source_reuses_safe_verdict(self):
        twin = "0x" + "55" * 20
        mapping = {SAFE: "safe", twin: "safe"}

        def fetch(address, chain, dest, api_key=None):
            out = Path(dest) / address.lower()
            if not out.exists():
                import shutil
                shutil.copytree(FIXTURES / mapping[address.lower()], out)
                (out / "bountyscan-meta.json").write_text("{}", encoding="utf-8")
            return out

        self.store.enqueue("ethereum", SAFE, "test")
        self.store.enqueue("ethereum", twin, "test")
        with mock.patch.object(auto, "fetch_verified_source", fetch):
            self.assertEqual(run_queue(self.store, self.cfg), {"safe": 2})
        note = self.store.fetch_one("ethereum", twin)["error"]
        self.assertIn("identical source", note)

    def test_backfill_unverified_is_final_immediately(self):
        self.store.enqueue_with("ethereum", PENDING, "backfill:blockscout", priority=1.0)
        with mock.patch.object(auto, "fetch_blockscout_source", fake_fetch), \
                mock.patch.object(auto, "fetch_verified_source", fake_fetch):
            run_queue(self.store, self.cfg)
        self.assertEqual(self.store.counts(), {"unverified_final": 1})

    def test_unverified_gives_up_after_max_attempts(self):
        self.cfg.max_attempts = 2
        self.store.enqueue("ethereum", PENDING, "test")
        with mock.patch.object(auto, "fetch_verified_source", fake_fetch):
            run_queue(self.store, self.cfg)
            run_queue(self.store, self.cfg)
        self.assertEqual(self.store.counts(), {"unverified_final": 1})

    def test_requeue_vulnerable_for_rejudging(self):
        self.store.enqueue("ethereum", VULN, "test")
        self.store.enqueue("ethereum", SAFE, "test")
        with mock.patch.object(auto, "fetch_verified_source", fake_fetch):
            run_queue(self.store, self.cfg)
        self.assertEqual(self.store.requeue_status("vulnerable", 2e9), 1)
        due = self.store.due()
        self.assertEqual([r["address"] for r in due], [VULN])
        self.assertEqual(due[0]["priority"], 2e9)
        with mock.patch.object(auto, "fetch_verified_source", fake_fetch):
            self.assertEqual(run_queue(self.store, self.cfg), {"vulnerable": 1})

    def test_minor_bugs_do_not_make_a_contract_vulnerable(self):
        minor = Path(self.tmp.name) / "minor"
        minor.mkdir()
        (minor / "Minor.sol").write_text(
            "pragma solidity ^0.8.20;\ncontract Minor {\n"
            "  function f(uint a, uint b, uint c) external pure returns (uint) { return a / b * c; }\n"
            "  function r() external view returns (uint) { return uint(keccak256(abi.encodePacked(block.timestamp))) % 10; }\n}\n",
            encoding="utf-8")
        (minor / "bountyscan-meta.json").write_text("{}", encoding="utf-8")
        self.store.enqueue("ethereum", PENDING, "test")
        with mock.patch.object(auto, "fetch_verified_source", lambda *a, **k: minor):
            self.assertEqual(run_queue(self.store, self.cfg), {"safe": 1})


if __name__ == "__main__":
    unittest.main()


class RelevanceTests(unittest.TestCase):
    def test_only_deployed_contract_and_parents_count(self):
        from bountyscan.scanner import relevant_contracts
        from bountyscan.solidity import parse_source
        src = ("pragma solidity ^0.8.0; contract Base {} contract Mid is Base {} contract Vault is Mid {}"
               " contract UnrelatedMock { function setX(uint x) external {} }")
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "B.sol"; p.write_text(src, encoding="utf-8")
            files = [parse_source(p)]
        self.assertEqual(relevant_contracts(files, ["Vault"]), {"Vault", "Mid", "Base"})
        self.assertIsNone(relevant_contracts(files, ["NotInBundle"]))
