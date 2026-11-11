// SPDX-License-Identifier: MIT
// Modern patterns that are NOT vulnerable (each was a false positive found by the 6-month backfill).
pragma solidity ^0.8.20;

interface IERC721Receiver { function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4); }

// Anyone may trigger fee withdrawal, but fees only ever reach the immutable feeRecipient.
contract FeeOrderBook {
    address public immutable feeRecipient;
    uint256 public accruedEthFees;
    constructor(address r) { feeRecipient = r; }
    function withdrawFees() external {
        uint256 amount = accruedEthFees;
        accruedEthFees = 0;
        _sendEth(feeRecipient, amount);
    }
    function _sendEth(address to, uint256 amount) private {
        (bool ok, ) = to.call{value: amount}("");
        require(ok);
    }
}

// ERC721 safeTransferFrom: the low-level call targets the receiver with a FIXED selector.
contract HookNFT {
    mapping(uint256 => address) public ownerOf;
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public {
        require(ownerOf[tokenId] == from && msg.sender == from);
        ownerOf[tokenId] = to;
        if (to.code.length > 0) {
            (bool ok, bytes memory ret) = to.call(
                abi.encodeWithSelector(IERC721Receiver.onERC721Received.selector, msg.sender, from, tokenId, data));
            require(ok && ret.length >= 32);
        }
    }
}

// ERC-4337 account: replay protection is the EntryPoint's nonce + chain-bound userOpHash.
struct PackedUserOperation { address sender; uint256 nonce; bytes signature; }
library ECDSA { function recover(bytes32, bytes memory) internal pure returns (address) { return address(0); } }
contract SimpleAccountLike {
    address public owner;
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash) internal view returns (uint256) {
        if (owner != ECDSA.recover(userOpHash, userOp.signature)) return 1;
        return 0;
    }
}
