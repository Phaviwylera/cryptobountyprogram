// Solady/Solmate Auth.setAuthority idiom: the authorization decision is computed into a boolean that
// then gates a revert — `bool ok = msg.sender == $.owner || auth.canCall(...); if (!ok) revert Unauthorized();`.
// A non-owner reverts with 0x82b42900 (Unauthorized()). Must NOT flag "privileged function callable by anyone".
pragma solidity ^0.8.20;

interface IAuthority { function canCall(address, address, bytes4) external view returns (bool); }

contract AuthUpgradeable {
    struct AuthStorage { address owner; IAuthority authority; }
    error Unauthorized();
    event AuthorityUpdated(address indexed by, IAuthority indexed authority);

    function _getAuthStorage() internal pure returns (AuthStorage storage $) {
        assembly { $.slot := 0 }
    }

    function setAuthority(IAuthority newAuthority) public virtual {
        AuthStorage storage $ = _getAuthStorage();
        IAuthority auth = $.authority;
        bool ok =
            msg.sender == $.owner || (address(auth) != address(0) && auth.canCall(msg.sender, address(this), msg.sig));
        if (!ok) {
            revert Unauthorized();
        }
        $.authority = newAuthority;
        emit AuthorityUpdated(msg.sender, newAuthority);
    }
}
