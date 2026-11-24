import json
import tempfile
import unittest
from pathlib import Path

from bountyscan.chain_audit import TargetAudit, load_protocol_names, write_protocol_map

A1 = "0x" + "a1" * 20


class ProtocolMapTests(unittest.TestCase):
    def test_write_and_load_roundtrip_and_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_protocol_map(tmp, [{"address": A1.upper(), "name": "Aave", "tvl": 5_000_000}])
            write_protocol_map(tmp, [{"address": "0x" + "b2" * 20, "name": "Curve", "tvl": 1_000_000}])
            names = load_protocol_names(tmp)
            self.assertEqual(names[A1.lower()], "Aave")           # stored lower-cased
            self.assertEqual(names["0x" + "b2" * 20], "Curve")    # second write merged, not clobbered

    def test_load_missing_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(load_protocol_names(tmp), {})

    def test_write_never_raises(self):
        write_protocol_map("/nonexistent\x00/x", [{"address": A1, "name": "X", "tvl": 1}])   # must not raise


class TargetAuditTests(unittest.TestCase):
    def test_record_merges_scan_and_payload_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = TargetAudit(tmp)
            # scan phase writes the outcome + patterns; payload phase later merges generators_run
            a.record(A1, name="Aave", tvl_usd=5_000_000.0, patterns_matched=1,
                     pattern_types=["reentrancy"], outcome="DISCARDED")
            a.record(A1, generators_run=1)
            j = json.loads(next(Path(tmp).glob("*.targets.json")).read_text())
            row = j[A1.lower()]
            self.assertEqual(row["name"], "Aave")
            self.assertEqual(row["outcome"], "DISCARDED")
            self.assertEqual(row["pattern_types"], ["reentrancy"])
            self.assertEqual(row["generators_run"], 1)            # merged, outcome not lost
            self.assertEqual(row["address"], A1.lower())

    def test_none_fields_do_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = TargetAudit(tmp)
            a.record(A1, outcome="CONFIRMED")
            a.record(A1, outcome=None, generators_run=2)          # None must not wipe the outcome
            row = json.loads(next(Path(tmp).glob("*.targets.json")).read_text())[A1.lower()]
            self.assertEqual(row["outcome"], "CONFIRMED")
            self.assertEqual(row["generators_run"], 2)

    def test_record_never_raises(self):
        TargetAudit("/nonexistent\x00/x").record(A1, outcome="ERROR")   # must not raise


if __name__ == "__main__":
    unittest.main()
