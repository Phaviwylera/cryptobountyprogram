// SPDX-License-Identifier: MIT
// Patterns from the 6-month backfill that are NOT vulnerable (each was flagged once).
pragma solidity ^0.8.20;

library ECDSA2 { function recover(bytes32, bytes memory) internal pure returns (address) { return address(0); } }
interface IERC20B { function transferFrom(address, address, uint256) external returns (bool); function transfer(address, uint256) external returns (bool); }

// 2FA-style: the signature must come from the caller themselves.
contract SelfSigned {
    mapping(address => bytes32) internal _keyOf;
    function verifySignature(address signer, bytes32 h, bytes memory sig) public pure returns (bool) {
        address recovered = ECDSA2.recover(h, sig);
        return recovered == signer;
    }
    function protect(bytes32 h, bytes memory sig, uint256 amount) external {
        address caller = msg.sender;
        require(verifySignature(caller, h, sig));
        _keyOf[caller] = bytes32(amount);
    }
}

// Versioned one-time initializer.
contract VersionedInit {
    uint256 public newMultiplier; uint256 public lastMultiplier;
    function initialize_v3() external { require(newMultiplier == 0); newMultiplier = lastMultiplier + 1; }
}

// burnFrom spending the allowance through a custom helper name.
contract SpendBurn {
    mapping(address => mapping(address => uint256)) public allowance; mapping(address => uint256) public balanceOf;
    function _spend(address from, uint256 v) internal { allowance[from][msg.sender] -= v; }
    function _burn(address from, uint256 v) internal { balanceOf[from] -= v; }
    function burnFrom(address from, uint256 value) external { _spend(from, value); _burn(from, value); }
}

// Role-gated executor: outsiders cannot re-enter.
contract RoleExecutor {
    mapping(bytes32 => uint256) internal _timestamps; mapping(address => bool) public isExecutor;
    modifier onlyRoleOrOpenRole(address a) { require(isExecutor[a]); _; }
    function execute(address target, bytes calldata payload, bytes32 id) external payable onlyRoleOrOpenRole(msg.sender) {
        (bool ok, ) = target.call{value: msg.value}(payload);
        require(ok);
        _timestamps[id] = 1;
    }
}

// Guard helper invoked on the caller.
contract MasterProxy {
    address internal master; address internal target;
    function requireMaster(address a) internal view { require(a == master); }
    function upgradeTarget(address newTarget) external { requireMaster(msg.sender); target = newTarget; }
}

// Renouncing your own role.
contract MinterRoleLike {
    mapping(address => bool) internal minters;
    function _removeMinter(address a) internal { minters[a] = false; }
    function renounceMinter() public { _removeMinter(msg.sender); }
}

// Calldata timelock (Morpho Vault V2).
contract TimelockedVault {
    mapping(bytes => uint256) public executableAt; mapping(address => bool) public isAllocator;
    function timelocked() internal view { require(executableAt[msg.data] != 0 && block.timestamp >= executableAt[msg.data]); }
    function setIsAllocator(address account, bool v) external { timelocked(); isAllocator[account] = v; }
}

// ERC-7540 claim: mint charged against the caller's own pending deposit.
contract AsyncVault {
    mapping(address => uint256) public claimableShares; mapping(address => uint256) public balanceOf;
    function _mint(uint256 shares, address receiver, address controller) internal {
        claimableShares[controller] -= shares; balanceOf[receiver] += shares;
    }
    function mint(uint256 shares, address receiver) public returns (uint256) { _mint(shares, receiver, msg.sender); return shares; }
}

// ERC-4337 paymaster: tx.origin identifies the approved bundler.
struct PackedUserOperation { address sender; bytes signature; }
contract PaymasterLike {
    mapping(address => bool) public bundler;
    function _validatePaymasterUserOp(PackedUserOperation calldata op) internal view returns (uint256) {
        if (!bundler[tx.origin]) return 1;
        op; return 0;
    }
}

// Chainlink Automation keeper: no caller-chosen value.
contract NavKeeper {
    uint256 public last;
    function checkUpkeep(bytes calldata) external view returns (bool, bytes memory) { return (block.timestamp > last + 1 days, ""); }
    function setMaxDeviation(bytes calldata) external { (bool ok, ) = this.checkUpkeep(""); require(ok); last = block.timestamp; }
}

// Chronicle-style oracle: strictly increasing age rejects replays.
contract ScribeLike {
    struct PokeData { uint128 val; uint32 age; }
    PokeData internal _pokeData; address public feed;
    error StaleMessage();
    function poke(PokeData calldata p, uint8 v, bytes32 r, bytes32 s) external {
        if (p.age <= _pokeData.age) revert StaleMessage();
        require(ecrecover(keccak256(abi.encode(p.val, p.age, block.chainid)), v, r, s) == feed && feed != address(0));
        _pokeData = p;
    }
}

// Unstake on behalf: the owner is both debited and paid.
contract OwnerUnstake {
    mapping(address => mapping(address => uint256)) public stakes;
    function unstake(address account, address token, uint256 amount) public {
        stakes[account][token] -= amount;
        require(IERC20B(token).transfer(account, amount));
    }
}
