import unittest
from unittest import mock

from bountyscan import discovery, value
from bountyscan.discovery import (custody_addresses, decode_address_array, llama_chain_name,
                                  parse_protocol_addresses, parse_protocol_rows)

A1 = "0x" + "a1" * 20
A2 = "0x" + "b2" * 20
A3 = "0x" + "c3" * 20


def _enc_addr_array(addrs):
    h = "%064x" % 32 + "%064x" % len(addrs)
    for a in addrs:
        h += "%064x" % int(a, 16)
    return "0x" + h


class CustodyResolutionTests(unittest.TestCase):
    def test_decode_address_array(self):
        self.assertEqual(decode_address_array(_enc_addr_array([A1, A2])), [A1, A2])
        self.assertEqual(decode_address_array(_enc_addr_array([])), [])
        self.assertEqual(decode_address_array("0x"), [])

    def test_custody_enumerates_compound_and_dedups(self):
        # Mock the on-chain reader: Compound returns cTokens (one duplicated); other sources empty.
        from bountyscan.discovery import AAVE_V3_POOL, COMPTROLLER, CURVE_REGISTRY, UNIV2_FACTORY
        empty_arr = _enc_addr_array([])
        zero = "0x" + "0" * 64

        def fake_call(rpc, to, data):
            if to == COMPTROLLER:
                return _enc_addr_array([A1, A2, A1])      # dup A1 -> deduped away
            if to == AAVE_V3_POOL:
                return empty_arr                           # getReservesList -> none
            return zero                                    # Curve pool_count / UniV2 length -> 0

        with mock.patch.object(value, "_call", fake_call), \
                mock.patch("bountyscan.rpc.RPC", lambda url: object()):
            rows = custody_addresses("http://rpc")
        self.assertEqual([r["address"] for r in rows], [A1.lower(), A2.lower()])   # deduped, order kept
        self.assertTrue(all(r["source"] == "compound" for r in rows))

    def test_custody_sources_isolated_failures_do_not_raise(self):
        # Every source errors; the function must still return (empty), never raise.
        def boom(rpc, to, data):
            raise RuntimeError("rpc down")
        with mock.patch.object(value, "_call", boom), mock.patch("bountyscan.rpc.RPC", lambda url: object()):
            self.assertEqual(custody_addresses("http://rpc"), [])


class DiscoveryParseTests(unittest.TestCase):
    def _payload(self):
        return [
            # qualifies: Ethereum, chain TVL above floor, chain-prefixed address
            {"name": "Big", "chains": ["Ethereum", "Arbitrum"], "chainTvls": {"Ethereum": 5_000_000},
             "tvl": 9_000_000, "address": f"ethereum:{A1}"},
            # qualifies: bare 0x address, overall tvl used (no chainTvls entry)
            {"name": "Mid", "chains": ["Ethereum"], "tvl": 250_000, "address": A2},
            # dropped: Ethereum TVL below floor even though overall is high
            {"name": "LowEth", "chains": ["Ethereum", "Base"], "chainTvls": {"Ethereum": 1_000}, "tvl": 8_000_000,
             "address": f"ethereum:{A3}"},
            # dropped: not on Ethereum
            {"name": "OtherChain", "chains": ["Solana"], "tvl": 50_000_000, "address": "solana:xyz"},
            # dropped: no resolvable address
            {"name": "NoAddr", "chains": ["Ethereum"], "tvl": 10_000_000, "address": None},
            # dropped: TVL not numeric -> treated as 0
            {"name": "BadTvl", "chains": ["Ethereum"], "tvl": "lots", "address": f"ethereum:{A1}"},
        ]

    def test_filters_by_chain_and_tvl_and_resolves_address(self):
        got = parse_protocol_addresses(self._payload(), min_tvl_usd=100_000.0, chain="Ethereum")
        self.assertEqual(got, [A1.lower(), A2.lower()])     # only the two that qualify, deduped, order kept

    def test_floor_excludes_everything_when_high(self):
        self.assertEqual(parse_protocol_addresses(self._payload(), min_tvl_usd=10_000_000.0, chain="Ethereum"), [])

    def test_ignores_malformed_rows(self):
        rows = [None, "nope", {"chains": "Ethereum"}, 42]      # must not raise
        self.assertEqual(parse_protocol_addresses(rows, 1.0, "Ethereum"), [])

    def test_chain_name_mapping(self):
        self.assertEqual(llama_chain_name("ethereum"), "Ethereum")
        self.assertEqual(llama_chain_name("mainnet"), "Ethereum")

    def test_rows_carry_name_and_tvl(self):
        rows = parse_protocol_rows(self._payload(), min_tvl_usd=100_000.0, chain="Ethereum")
        self.assertEqual([r["address"] for r in rows], [A1.lower(), A2.lower()])
        self.assertEqual(rows[0]["name"], "Big")
        self.assertEqual(rows[0]["tvl"], 5_000_000)     # chain TVL used when present
        self.assertEqual(rows[1]["name"], "Mid")
        self.assertEqual(rows[1]["tvl"], 250_000)       # overall tvl used when no chainTvls entry


if __name__ == "__main__":
    unittest.main()
