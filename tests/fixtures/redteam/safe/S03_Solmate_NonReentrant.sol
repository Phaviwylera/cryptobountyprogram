// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
abstract contract ReentrancyGuard {
    uint256 private locked = 1;
    modifier nonReentrant() virtual { require(locked == 1, "REENTRANCY"); locked = 2; _; locked = 1; }
}
contract SolmateVault is ReentrancyGuard {
    mapping(address => uint256) public shares;
    function deposit() external payable { shares[msg.sender] += msg.value; }
    function redeem(uint256 amount) external nonReentrant {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        shares[msg.sender] -= amount;
    }
}
