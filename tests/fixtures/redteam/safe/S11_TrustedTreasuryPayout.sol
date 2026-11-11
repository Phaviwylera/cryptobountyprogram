// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Fee sweep to an immutable treasury; bookkeeping timestamp written afterwards.
// The callee is a fixed trusted address and all balances are settled before the call.
contract FeeCollector {
    address payable public immutable treasury;
    uint256 public accrued;
    uint256 public lastSweep;
    constructor(address payable t) { treasury = t; }
    receive() external payable { accrued += msg.value; }
    function sweep() external {
        uint256 amt = accrued;
        accrued = 0;
        (bool ok, ) = treasury.call{value: amt}("");
        require(ok);
        lastSweep = block.timestamp;
    }
}
