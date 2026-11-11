// Bridge withdraw with a `pendingWithdrawals[hash].to != address(0)` single-use flag:
// the signed hash binds to a `clientWithdrawId` and the pending map prevents re-use.
// Must NOT flag as "signatures can be replayed".
pragma solidity ^0.8.20;

contract EdgexBridgeLike {
    struct Pending { address to; address token; uint256 amount; }
    mapping(bytes32 => Pending) public pendingWithdrawals;
    address public releaser;

    error OrderAlreadyExecuted(bytes32 h);

    function withdrawalSigHash(address to, uint256 amount, address token, uint256 expireTime,
                                uint256 clientWithdrawId, uint256 chainId) public view returns (bytes32) {
        return keccak256(abi.encodePacked("ERC20", to, amount, token, expireTime, clientWithdrawId, address(this), chainId));
    }

    function withdraw(address to, uint256 amount, address token, uint256 expireTime,
                      uint256 clientWithdrawId, bytes calldata signature) external {
        bytes32 h = withdrawalSigHash(to, amount, token, expireTime, clientWithdrawId, block.chainid);
        if (pendingWithdrawals[h].to != address(0)) revert OrderAlreadyExecuted(h);
        // ecrecover against `releaser` omitted for brevity; the single-use flag is the replay guard.
        pendingWithdrawals[h] = Pending(to, token, amount);
    }
}
