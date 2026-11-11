// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library Address {
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok);
        return ret;
    }
}
// Executor using Address.functionCall(target, data) with caller-supplied target
contract RouterExecutor {
    function execute(address target, bytes calldata data) external payable returns (bytes memory) {
        return Address.functionCall(target, data);
    }
}
