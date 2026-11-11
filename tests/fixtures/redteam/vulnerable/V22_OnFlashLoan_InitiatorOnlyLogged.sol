// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
// Lender checked, but initiator is only emitted - anyone can start a loan into this contract
contract FlashLeverage {
    address public immutable lender;
    event Loan(address initiator, uint256 amount);
    constructor(address l) { lender = l; }
    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata data) external returns (bytes32) {
        require(msg.sender == lender, "lender");
        emit Loan(initiator, amount);
        (address to) = abi.decode(data, (address));
        IERC20(token).transfer(to, amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
