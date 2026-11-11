// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
// Cream (AMP) / imBTC-Uniswap V1: ERC777 tokensReceived hook fires inside transfer()
contract CreamLikeMarket {
    IERC20 public immutable underlying;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public accountBorrows;
    constructor(IERC20 u) { underlying = u; }
    function borrow(uint256 amount) external {
        require(collateral[msg.sender] >= accountBorrows[msg.sender] + amount, "ltv");
        require(underlying.transfer(msg.sender, amount));
        accountBorrows[msg.sender] += amount;
    }
}
