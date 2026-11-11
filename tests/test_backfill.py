import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from bountyscan import backfill as bfmod
from bountyscan import value
from bountyscan.state import LIVE_PRIORITY, Store


def item(addr, name, txs=0, bal=0, days_ago=1, lang="solidity"):
    ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    return {"address": {"hash": addr, "name": name}, "transactions_count": txs, "coin_balance": str(bal),
            "market_cap": None, "verified_at": ts, "language": lang}


A = lambda n: "0x" + f"{n:040x}"


class MulticallCodecTests(unittest.TestCase):
    def test_decode_aggregate3_result(self):
        # (bool success, bytes returnData)[] with two entries: (true, 32-byte 7) and (false, empty)
        w = lambda n: "%064x" % n
        el1 = w(1) + w(0x40) + w(32) + w(7)
        el2 = w(0) + w(0x40) + w(0)
        body = w(0x20) + w(2) + w(0x40) + w(0x40 + len(el1) // 2) + el1 + el2
        out = value.decode_aggregate3("0x" + body)
        self.assertEqual(out[0], (True, (7).to_bytes(32, "big")))
        self.assertEqual(out[1], (False, b""))

    def test_encode_aggregate3_layout(self):
        data = bytes.fromhex("70a08231") + b"\x11" * 32          # 36 bytes -> padded to 64
        enc = bytes.fromhex(value.encode_aggregate3([(value.MULTICALL3, data)])[2:])
        self.assertEqual(enc[:4].hex(), value.AGGREGATE3)
        word = lambda o: int.from_bytes(enc[4 + o:4 + o + 32], "big")
        self.assertEqual(word(0), 0x20)          # offset to array
        self.assertEqual(word(32), 1)            # length
        el = 4 + 64 + word(64)                   # first element (offset is relative to after length)
        self.assertEqual(int.from_bytes(enc[el:el + 32], "big"), int(value.MULTICALL3, 16))
        self.assertEqual(int.from_bytes(enc[el + 96:el + 128], "big"), 36)


class BackfillTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "s.db")

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def test_alive_filter(self):
        self.assertFalse(bfmod.alive(item(A(1), "X", txs=2), 10))
        self.assertTrue(bfmod.alive(item(A(1), "X", txs=10), 10))
        self.assertTrue(bfmod.alive(item(A(1), "X", txs=0, bal=5), 10))

    def test_run_filters_prices_and_queues_richest_first(self):
        pages = {
            None: ([item(A(1), "Vault", txs=500), item(A(2), "SafeProxy", txs=900), item(A(3), "Dead", txs=1),
                    item(A(4), "Pool", txs=40), item(A(5), "VyperThing", txs=99, lang="vyper")], 777),
            777: ([item(A(6), "Token", txs=60, days_ago=3), item(A(7), "Ancient", txs=999, days_ago=400)], 555),
        }
        prices = {A(1): 2_500_000.0, A(4): 10.0, A(6): 0.0}
        fake_pages = lambda chain, cursor: pages[cursor]
        fake_value = lambda rpc, cid, addrs: {a.lower(): {"usd": prices.get(a, 0.0), "items": [], "priced": True} for a in addrs}
        bf = bfmod.Backfill(self.store, rpc=object())
        with mock.patch.object(bfmod, "blockscout_verified_page", fake_pages), \
                mock.patch.object(bfmod, "holdings_many", fake_value), \
                mock.patch.object(bfmod.threading.Thread, "start", lambda self: None):
            bf.start("ethereum", days=180, min_txs=10)
            bf._run()
        st = bf.snapshot()
        self.assertTrue(st["done"])                          # stopped at the 400-day-old item
        self.assertEqual(st["skipped_wallets"], 1)           # SafeProxy
        self.assertEqual(st["queued"], 3)                    # Vault, Pool, Token (Dead too quiet, Vyper skipped)
        order = [r["address"] for r in self.store.due(10)]
        self.assertEqual(order[0], A(1).lower())             # $2.5M vault first
        self.assertNotIn(A(7).lower(), order)
        self.assertEqual(self.store.fetch_one("ethereum", A(1))["value_usd"], 2_500_000.0)

    def test_live_items_jump_ahead_of_backfill(self):
        self.store.enqueue_with("ethereum", A(1), "backfill:blockscout", priority=9_999_999.0)
        self.store.enqueue("ethereum", A(2), "block:1")
        self.assertEqual(self.store.fetch_one("ethereum", A(2))["priority"], LIVE_PRIORITY)
        self.assertEqual(self.store.due(1)[0]["address"], A(2).lower())

    def test_progress_persists_for_resume(self):
        bf = bfmod.Backfill(self.store, rpc=None)
        with mock.patch.object(bfmod.threading.Thread, "start", lambda self: None):
            bf.start("ethereum", days=30, min_txs=5)
        bf.state["cursor"] = 4242
        bf._save()
        again = bfmod.Backfill(self.store, rpc=None)
        self.assertEqual(again.state["cursor"], 4242)
        self.assertEqual(again.state["days"], 30)


if __name__ == "__main__":
    unittest.main()
