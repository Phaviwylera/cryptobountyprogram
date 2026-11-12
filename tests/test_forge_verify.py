import types
import unittest

from bountyscan.forge_verify import (AUTO_VERIFIABLE, build_exploit, canonical_sig, parse_outcome)
from bountyscan.solidity import Function, Param


def _fn(name, params):
    return Function(kind="function", name=name, contract=None,
                    params=[Param(type=t, name=n) for t, n in params],
                    visibility="external", mutability=None, modifiers=[], body="{}", body_offset=0, offset=0)


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

    def test_report_line_present(self):
        v = parse_outcome(_finding("unrestricted-mint"), "CALL_OK true\nTOKEN_DELTA 5\nATTACKER_WEI_DELTA 0")
        self.assertIn("Payload attack: CONFIRMED", v.report_line())


if __name__ == "__main__":
    unittest.main()
