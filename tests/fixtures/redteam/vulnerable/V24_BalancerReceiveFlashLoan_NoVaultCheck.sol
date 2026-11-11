// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
// receiveFlashLoan uses msg.sender only to repay - never checks msg.sender == balancerVault
contract BalancerArb {
    function receiveFlashLoan(IERC20[] memory tokens, uint256[] memory amounts, uint256[] memory feeAmounts, bytes memory userData) external {
        address to = abi.decode(userData, (address));
        for (uint256 i = 0; i < tokens.length; i++) {
            tokens[i].transfer(to, amounts[i]);
            tokens[i].transfer(msg.sender, amounts[i] + feeAmounts[i]);
        }
    }
}
