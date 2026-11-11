// Chainlink AccessControlledOffchainAggregator-style owner fallback:
// `require(msg.sender == owner || tx.origin == owner)` is NOT a phishable auth path -
// owner is a protocol-set address, the caller is still checked against it, and tx.origin
// is just the EOA convenience branch. Must NOT flag as "Authorization via tx.origin".
pragma solidity ^0.8.20;

contract Aggregator {
    address public owner;
    function hasAccess(address user, bytes memory) public view returns (bool) {
        return user == owner;
    }
    function latestAnswer() external view returns (int256) {
        require(msg.sender == owner || tx.origin == owner, "No access");
        return 42;
    }
}
