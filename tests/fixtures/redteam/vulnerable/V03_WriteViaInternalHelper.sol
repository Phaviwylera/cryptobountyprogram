// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// State is zeroed in an internal helper AFTER the external call
contract HelperWriteVault {
    mapping(address => uint256) public credit;
    function deposit() external payable { credit[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amt = credit[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        _clear(msg.sender);
    }
    function _clear(address who) internal { credit[who] = 0; }
}
