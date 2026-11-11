// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
// Only checks the caller-supplied `sender` arg, never msg.sender == pair
contract FlashArb {
    function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
        require(sender == address(this), "not self");
        (address token, uint256 repay) = abi.decode(data, (address, uint256));
        IERC20(token).transfer(msg.sender, repay);
        amount0; amount1;
    }
}
