// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function balanceOf(address) external view returns (uint256); }
// A balance sanity check that mentions msg.sender is mistaken for access control
contract AggregatorWithBalanceCheck {
    function swap(address tokenIn, uint256 amountIn, address router, bytes calldata routerData) external {
        require(IERC20(tokenIn).balanceOf(msg.sender) >= amountIn, "balance");
        (bool ok, ) = router.call(routerData);
        require(ok, "router");
    }
}
