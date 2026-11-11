// Privileged setters gated by a role-checking modifier `checkAccess(UPGRADER_ROLE)` whose body
// delegates the role check to an external authority (Privacy Pools PoolVault / TransactVerifierRouter).
// Must NOT flag "privileged function callable by anyone".
pragma solidity ^0.8.20;

interface IAuthority { function checkRole(bytes32 role) external view; }

contract PoolVault {
    bytes32 constant UPGRADER_ROLE = keccak256("UPGRADER");
    IAuthority internal _authority;
    address public verifier;
    address public aspRegistry;

    modifier checkAccess(bytes32 r) {
        _authority.checkRole(r);
        _;
    }

    function setVerifier(address v) external checkAccess(UPGRADER_ROLE) {
        verifier = v;
    }

    function setAspRegistry(address r) external checkAccess(UPGRADER_ROLE) {
        aspRegistry = r;
    }
}
