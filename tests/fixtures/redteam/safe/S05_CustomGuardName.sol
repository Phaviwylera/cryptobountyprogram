// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Guard modifier with a non-standard name
contract CustomGuardVault {
    uint256 private _entered;
    modifier noReenter() { require(_entered == 0, "re"); _entered = 1; _; _entered = 0; }
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external noReenter {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
