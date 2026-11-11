// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract EtherStore {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0);
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "fail");
        balances[msg.sender] = 0;
    }
}
