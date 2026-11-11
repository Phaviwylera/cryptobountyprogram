// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// MasterChef emergencyWithdraw with a storage pointer written after the call
contract ChefLike {
    struct UserInfo { uint256 amount; uint256 rewardDebt; }
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    function deposit(uint256 pid) external payable { userInfo[pid][msg.sender].amount += msg.value; }
    function emergencyWithdraw(uint256 pid) external {
        UserInfo storage user = userInfo[pid][msg.sender];
        (bool ok, ) = msg.sender.call{value: user.amount}("");
        require(ok);
        user.amount = 0;
        user.rewardDebt = 0;
    }
}
