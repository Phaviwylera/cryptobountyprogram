// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transferFrom(address, address, uint256) external returns (bool); }
// Mint callback pulls from a payer decoded from calldata, no pool check
contract LiquidityManager {
    struct MintCallbackData { address token0; address token1; address payer; }
    function uniswapV3MintCallback(uint256 amount0Owed, uint256 amount1Owed, bytes calldata data) external {
        MintCallbackData memory d = abi.decode(data, (MintCallbackData));
        if (amount0Owed > 0) IERC20(d.token0).transferFrom(d.payer, msg.sender, amount0Owed);
        if (amount1Owed > 0) IERC20(d.token1).transferFrom(d.payer, msg.sender, amount1Owed);
    }
}
