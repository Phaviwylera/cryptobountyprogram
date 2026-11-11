// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
interface IUniswapV3Factory { function getPool(address, address, uint24) external view returns (address); }
library CallbackValidation {
    function verifyCallback(address factory, address tokenA, address tokenB, uint24 fee) internal view returns (address pool) {
        pool = IUniswapV3Factory(factory).getPool(tokenA, tokenB, fee);
        require(msg.sender == pool, "pool");
    }
}
contract SafeSwapRouter {
    address public immutable factory;
    constructor(address f) { factory = f; }
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        (address tokenIn, address tokenOut, uint24 fee) = abi.decode(data, (address, address, uint24));
        CallbackValidation.verifyCallback(factory, tokenIn, tokenOut, fee);
        uint256 owed = amount0Delta > 0 ? uint256(amount0Delta) : uint256(amount1Delta);
        IERC20(tokenIn).transfer(msg.sender, owed);
    }
}
