// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
contract SafeBalancerArb {
    address public immutable vault;
    bool private inFlash;
    constructor(address v) { vault = v; }
    function receiveFlashLoan(IERC20[] memory tokens, uint256[] memory amounts, uint256[] memory feeAmounts, bytes memory userData) external {
        require(msg.sender == vault, "vault");
        require(inFlash, "not initiated");
        userData;
        for (uint256 i = 0; i < tokens.length; i++) tokens[i].transfer(vault, amounts[i] + feeAmounts[i]);
    }
}
