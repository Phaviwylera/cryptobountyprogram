// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function approve(address, uint256) external returns (bool); }
contract SafeFlashBorrower {
    address public immutable lender;
    constructor(address l) { lender = l; }
    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata data) external returns (bytes32) {
        require(msg.sender == lender, "untrusted lender");
        require(initiator == address(this), "untrusted initiator");
        IERC20(token).approve(lender, amount + fee);
        data;
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
