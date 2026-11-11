// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Fei Rari / Cream: borrow() is guarded but sends ETH before recording debt;
// the attacker re-enters the UNGUARDED exitMarket() and withdraws collateral.
contract RariLikeMarket {
    uint256 private _status = 1;
    modifier nonReentrant() { require(_status == 1); _status = 2; _; _status = 1; }
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public accountBorrows;
    mapping(address => bool) public inMarket;
    function supply() external payable { collateral[msg.sender] += msg.value; inMarket[msg.sender] = true; }
    function borrow(uint256 amount) external nonReentrant {
        require(inMarket[msg.sender] && collateral[msg.sender] >= accountBorrows[msg.sender] + amount * 2);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        accountBorrows[msg.sender] += amount;
    }
    function exitMarket() external {
        require(accountBorrows[msg.sender] == 0, "has debt");
        inMarket[msg.sender] = false;
        uint256 c = collateral[msg.sender];
        collateral[msg.sender] = 0;
        payable(msg.sender).transfer(c);
    }
}
