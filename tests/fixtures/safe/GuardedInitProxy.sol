// SPDX-License-Identifier: MIT
// Proxy whose initializer can only run once (Aave InitializableUpgradeabilityProxy pattern).
pragma solidity ^0.8.20;

contract GuardedInitProxy {
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function _implementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { impl := sload(slot) }
    }

    function initialize(address logic, bytes memory data) public payable {
        require(_implementation() == address(0));
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { sstore(slot, logic) }
        if (data.length > 0) {
            (bool success, ) = logic.delegatecall(data);
            require(success);
        }
    }
}
