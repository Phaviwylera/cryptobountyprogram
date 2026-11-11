// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library Address {
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok);
        return ret;
    }
}
interface IStrategy { function harvest(uint256) external; }
// Delegatecall target is a caller-supplied address, calldata built locally
contract StrategyRunner {
    using Address for address;
    address public owner = msg.sender;
    function harvestWith(address strategy, uint256 minOut) external {
        strategy.functionDelegateCall(abi.encodeCall(IStrategy.harvest, (minOut)));
    }
}
