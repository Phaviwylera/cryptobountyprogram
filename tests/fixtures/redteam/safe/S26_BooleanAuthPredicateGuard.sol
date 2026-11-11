// Privileged setter guarded by `if (!_isVaultOwner() && !_isManagerAdmin()) revert` using no-arg boolean
// auth predicates that each `return msg.sender == <owner/manager>`. Arrakis UniV4StandardModule pattern.
// Must NOT flag "privileged function callable by anyone".
pragma solidity ^0.8.20;

interface IOwnable { function owner() external view returns (address); }

contract Module {
    IOwnable public metaVault;
    address public managerAdmin;
    bool public feeClaim;
    error OnlyManagerAdminOrVaultOwner();

    function _isVaultOwner() internal view returns (bool) {
        return msg.sender == metaVault.owner();
    }

    function _isManagerAdmin() internal view returns (bool) {
        return msg.sender == managerAdmin;
    }

    function setFeeClaim(bool feeClaim_) external {
        if (!_isVaultOwner() && !_isManagerAdmin()) {
            revert OnlyManagerAdminOrVaultOwner();
        }
        feeClaim = feeClaim_;
    }
}
