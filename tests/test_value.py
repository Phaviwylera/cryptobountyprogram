import tempfile
import unittest
from pathlib import Path

from bountyscan import value
from bountyscan.state import Store

USDC = value.TOKENS[1][0][1]
WETH = next(t[1] for t in value.TOKENS[1] if t[0] == "WETH")
ETH_FEED = value.FEEDS[1]["eth"]


class FakeRPC:
    """Answers eth_call like mainnet would, for a contract holding 2,500 USDC + 1.5 WETH + 0.5 ETH."""
    def call(self, method, params):
        to, data = params[0]["to"], params[0]["data"]
        word = lambda n: "%064x" % n
        if to == ETH_FEED and data == value.LATEST_ROUND:
            import time
            return "0x" + word(1) + word(2000 * 10**8) + word(0) + word(int(time.time())) + word(1)
        if to == ETH_FEED and data == value.DECIMALS:
            return "0x" + word(8)
        if data.startswith(value.BALANCE_OF):
            return "0x" + word({USDC: 2500 * 10**6, WETH: 15 * 10**17}.get(to, 0))
        if data == value.STETH_PER_TOKEN:
            return "0x" + word(12 * 10**17)
        return "0x" + word(0)


class ValueTests(unittest.TestCase):
    def setUp(self):
        value._price_cache.clear()

    def test_counts_tokens_not_just_native(self):
        h = value.holdings(FakeRPC(), 1, "0x" + "11" * 20, 5 * 10**17)
        syms = {i["symbol"]: i for i in h["items"]}
        self.assertEqual(syms["USDC"]["usd"], 2500.0)
        self.assertEqual(syms["WETH"]["usd"], 3000.0)
        self.assertEqual(syms["native"]["usd"], 1000.0)
        self.assertEqual(h["usd"], 6500.0)
        self.assertEqual(h["items"][0]["symbol"], "WETH")          # sorted by value
        self.assertIn("$6,500.00", value.describe(h))

    def test_empty_contract_is_zero_not_unknown(self):
        class Empty(FakeRPC):
            def call(self, method, params):
                if params[0]["data"].startswith(value.BALANCE_OF):
                    return "0x" + "0" * 64
                return super().call(method, params)
        h = value.holdings(Empty(), 1, "0x" + "22" * 20, 0)
        self.assertEqual(h["usd"], 0)
        self.assertEqual(h["items"], [])

    def test_unknown_chain_is_unpriced(self):
        h = value.holdings(FakeRPC(), 999999, "0x" + "33" * 20, 10**18)
        self.assertIsNone(h["usd"])

    def test_store_migrates_old_database(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "old.db"
            db = sqlite3.connect(p)
            db.execute("CREATE TABLE contracts (chain TEXT, address TEXT, origin TEXT, status TEXT DEFAULT 'queued', "
                       "attempts INTEGER DEFAULT 0, next_try REAL DEFAULT 0, name TEXT, max_severity TEXT, findings INTEGER, "
                       "balance_wei TEXT, report TEXT, error TEXT, updated REAL, PRIMARY KEY (chain, address))")
            db.commit(); db.close()
            s = Store(p)
            s.enqueue("ethereum", "0x" + "44" * 20, "t")
            s.update("ethereum", "0x" + "44" * 20, status="vulnerable", value_usd=1234.5)
            self.assertEqual(s.value_stats()["vulnerable_usd"], 1234.5)
            s.db.close()


if __name__ == "__main__":
    unittest.main()
