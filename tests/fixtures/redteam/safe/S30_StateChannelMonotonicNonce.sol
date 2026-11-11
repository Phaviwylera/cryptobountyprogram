// State-channel update (Lithium/Perun/Raiden shape): signature verification and the replay guard live in
// delegated LIBRARIES, not the contract family. Replay is prevented by a MONOTONIC struct-field nonce -
// `if (newNonce <= ch.nonce) revert InvalidNonce()` - so a higher nonce overrides and an old-nonce signed
// state cannot be replayed. Must NOT flag "signatures can be replayed".
pragma solidity ^0.8.20;

library SigLib {
    function recoverSigner(bytes32 h, bytes memory) internal pure returns (address) {
        return ecrecover(h, 27, bytes32(0), bytes32(0));
    }
}

library ChannelLib {
    struct Channel { uint256 nonce; uint256 balance; address owner; }
    error InvalidNonce();

    function update(Channel storage ch, uint256 newNonce, uint256 newBalance, bytes memory sig) internal {
        bytes32 h = keccak256(abi.encodePacked(newNonce, newBalance, block.chainid, address(this)));
        address signer = SigLib.recoverSigner(h, sig);
        require(signer == ch.owner, "bad sig");
        if (newNonce <= ch.nonce) revert InvalidNonce();   // monotonic replay guard
        ch.nonce = newNonce;
        ch.balance = newBalance;
    }
}

contract Channels {
    mapping(bytes32 => ChannelLib.Channel) internal store;

    function updateChannel(bytes32 id, uint256 newNonce, uint256 newBalance, bytes calldata sig) external {
        ChannelLib.update(store[id], newNonce, newBalance, sig);
    }
}
