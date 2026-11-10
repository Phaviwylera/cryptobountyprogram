// SPDX-License-Identifier: MIT
// INTENTIONALLY VULNERABLE - BEC "batchOverflow" (CVE-2018-10299) pattern. Never deploy.
pragma solidity ^0.4.24;

contract BatchOverflowToken {
    mapping(address => uint256) public balances;

    function batchTransfer(address[] _receivers, uint256 _value) public returns (bool) {
        uint cnt = _receivers.length;
        uint256 amount = uint256(cnt) * _value;
        require(cnt > 0 && cnt <= 20);
        require(_value > 0 && balances[msg.sender] >= amount);
        balances[msg.sender] = balances[msg.sender] - amount;
        for (uint i = 0; i < cnt; i++) {
            balances[_receivers[i]] = balances[_receivers[i]] + _value;
        }
        return true;
    }
}
