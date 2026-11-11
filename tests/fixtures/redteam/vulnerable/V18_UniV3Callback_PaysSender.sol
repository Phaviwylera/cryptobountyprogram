// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
// Unprotected uniswapV3SwapCallback: anyone calls it and is paid as "the pool"
contract SwapBot {
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        (address token0, address token1) = abi.decode(data, (address, address));
        if (amount0Delta > 0) IERC20(token0).transfer(msg.sender, uint256(amount0Delta));
        else IERC20(token1).transfer(msg.sender, uint256(amount1Delta));
    }
}
