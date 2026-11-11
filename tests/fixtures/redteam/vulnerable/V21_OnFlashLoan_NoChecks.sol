// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function approve(address, uint256) external returns (bool); }
contract FlashBorrower {
    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata data) external returns (bytes32) {
        address spender = abi.decode(data, (address));
        IERC20(token).approve(spender, type(uint256).max);
        initiator; amount; fee;
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
