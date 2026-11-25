import unittest
from unittest import mock

from bountyscan import pricing, value

A = "0x" + "a1" * 20
B = "0x" + "b2" * 20


class SumPricedTests(unittest.TestCase):
    def test_values_priced_tokens_only(self):
        balances = {A: 2 * 10**18, B: 5 * 10**6}
        decimals = {A: 18, B: 6}
        prices = {A: 3.0}                      # B has no price -> contributes nothing
        self.assertEqual(pricing.sum_priced(balances, decimals, prices), 6.0)

    def test_unknown_decimals_skipped(self):
        self.assertEqual(pricing.sum_priced({A: 10**18}, {}, {A: 5.0}), 0.0)

    def test_zero_balance_skipped(self):
        self.assertEqual(pricing.sum_priced({A: 0}, {A: 18}, {A: 5.0}), 0.0)


class ExtendedValueTests(unittest.TestCase):
    def test_returns_zero_when_rpc_fails(self):
        def boom(rpc, to, data):
            raise RuntimeError("rpc down")
        with mock.patch.object(value, "_call", boom):
            self.assertEqual(pricing.extended_token_value_usd(object(), A), 0.0)

    def test_prices_held_token_via_defillama(self):
        # One token in the set shows a balance; price it via a mocked DeFiLlama call.
        tok = pricing.EXTENDED_TOKENS[0]      # (symbol, address, decimals)
        tok_addr = tok[1].lower()

        def fake_multicall_call(rpc, to, data):
            # pretend Multicall3 returned a single nonzero balance for the first token, zero for the rest
            from bountyscan.value import decode_aggregate3  # noqa: F401 (not used; we monkeypatch decode)
            return "0xMARKER"

        def fake_decode(hexdata):
            # one nonzero (2 whole tokens) then zeros
            n = len(pricing.EXTENDED_TOKENS)
            res = [(True, (2 * 10**tok[2]).to_bytes(32, "big"))]
            res += [(True, (0).to_bytes(32, "big")) for _ in range(n - 1)]
            return res

        with mock.patch.object(value, "_call", fake_multicall_call), \
                mock.patch.object(value, "decode_aggregate3", fake_decode), \
                mock.patch.object(value, "encode_aggregate3", lambda calls: "0x"), \
                mock.patch.object(pricing, "defillama_prices", lambda addrs, **k: {tok_addr: 4.0}):
            v = pricing.extended_token_value_usd(object(), A)
        self.assertEqual(v, 8.0)              # 2 tokens * $4


class DefillamaPriceCacheTests(unittest.TestCase):
    def test_cache_prevents_refetch(self):
        pricing._price_cache.clear()
        calls = {"n": 0}

        class FakeResp:
            def __init__(self, body): self.body = body
            def read(self): return self.body
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, timeout=0):
            calls["n"] += 1
            return FakeResp(b'{"coins": {"ethereum:' + A.lower().encode() + b'": {"price": 2.5}}}')

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            p1 = pricing.defillama_prices([A])
            p2 = pricing.defillama_prices([A])      # served from cache
        self.assertEqual(p1[A.lower()], 2.5)
        self.assertEqual(p2[A.lower()], 2.5)
        self.assertEqual(calls["n"], 1)             # only one network fetch


if __name__ == "__main__":
    unittest.main()
