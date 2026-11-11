// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Custom inline mutex (pre-OZ style, e.g. Synthetix/early Uniswap forks)
contract InlineMutexVault {
    bool private locked;
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        require(!locked, "locked");
        locked = true;
        uint256 bal = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        locked = false;
    }
}
