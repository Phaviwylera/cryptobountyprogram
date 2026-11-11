// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
interface IUniswapV2Pair { function token0() external view returns (address); function token1() external view returns (address); }
interface IUniswapV2Factory { function getPair(address, address) external view returns (address); }
contract SafeFlashArb {
    address public immutable factory;
    constructor(address f) { factory = f; }
    function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
        address t0 = IUniswapV2Pair(msg.sender).token0();
        address t1 = IUniswapV2Pair(msg.sender).token1();
        require(msg.sender == IUniswapV2Factory(factory).getPair(t0, t1), "not pair");
        require(sender == address(this), "not self");
        uint256 repay = abi.decode(data, (uint256));
        IERC20(amount0 > 0 ? t0 : t1).transfer(msg.sender, repay + amount1 * 0);
    }
}
