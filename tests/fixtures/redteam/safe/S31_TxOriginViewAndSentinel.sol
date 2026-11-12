// tx.origin in a VIEW access predicate (Chainlink SimpleReadAccessController.hasAccess returning
// `_user == tx.origin`; anti-bot `_isOrigin`) and against a gas-estimation SENTINEL constant (Optimism
// `tx.origin == ESTIMATION_ADDRESS`). None is a phishable fund-moving authorization - the views move
// nothing and the sentinel branch is a special gas-estimation mode. Must NOT flag "Authorization via tx.origin".
pragma solidity ^0.8.20;

contract ReadAccess {
    mapping(address => bool) accessList;
    bool checkEnabled;
    address constant ESTIMATION_ADDRESS = address(1);
    uint256 public x;

    function hasAccess(address _user, bytes memory) public view virtual returns (bool) {
        return accessList[_user] || !checkEnabled || _user == tx.origin;
    }

    function _isOrigin(address account) internal view returns (bool) {
        return account == tx.origin;
    }

    function poke() external {
        // gas-estimation sentinel branch, not authorization
        if (tx.origin == ESTIMATION_ADDRESS) {
            x = 1;
        }
    }
}
