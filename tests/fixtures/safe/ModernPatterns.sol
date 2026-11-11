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

// Opyn-style pricer and Pyth adapter: permissionless pokes; the price comes from a trusted source.
interface IOracleLike { function getExpiryPrice(address, uint256) external view returns (uint256, bool); function setExpiryPrice(address, uint256, uint256) external; }
interface IPythLike { function getUpdateFee(bytes[] calldata) external view returns (uint256); function updatePriceFeeds(bytes[] calldata) external payable; }
contract PokePricer {
    IOracleLike public oracle; address public underlying; address public lpToken;
    function setExpiryPriceInOracle(uint256 _expiryTimestamp) external {
        (uint256 p, ) = oracle.getExpiryPrice(underlying, _expiryTimestamp);
        oracle.setExpiryPrice(lpToken, _expiryTimestamp, p * 2);
    }
}
contract PythAdapterLike {
    IPythLike public pyth;
    function updatePrice(address asset, bytes calldata priceUpdate) external payable {
        bytes[] memory d = new bytes[](1); d[0] = priceUpdate;
        pyth.updatePriceFeeds{value: pyth.getUpdateFee(d)}(d);
    }
}

// ERC-1271 validator (AirSwap RFQ style): the consuming protocol owns the nonce bookkeeping.
contract Erc1271Bot {
    address internal _rfqSigner;
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        return _validateSignature(hash, signature);
    }
    function _validateSignature(bytes32 hash, bytes memory signature) internal view returns (bytes4) {
        address recovered = ECDSA.recover(hash, signature);
        require(recovered != address(0) && recovered == _rfqSigner);
        return 0x1626ba7e;
    }
}

// Gnosis Safe layout: signatures recovered in a parent, replay nonce kept by the child.
contract SigDecoder {
    function recoverKey(bytes32 messageHash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        return ecrecover(messageHash, v, r, s);
    }
}
contract SafeLike is SigDecoder {
    uint256 public nonce;
    address public owner;
    function execTransaction(bytes32 txHash, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 h = keccak256(abi.encode(txHash, nonce++, block.chainid));
        require(recoverKey(h, v, r, s) == owner);
    }
}

// Manifold creator style: metadata setters gated by a requireExtension() helper.
contract CreatorLike {
    mapping(address => bool) internal _extensions;
    mapping(address => string) internal _base;
    function requireExtension() internal view { require(_extensions[msg.sender], "Must be registered extension"); }
    function setBaseTokenURIExtension(string calldata uri) external { requireExtension(); _base[msg.sender] = uri; }
    function setRoyaltiesExtension(address payable receiver) external { requireExtension(); receiver; }
}

// Signature-gated rescue (relayer flow) with a consumed per-id nonce.
contract SignedRescue {
    address public signer;
    mapping(bytes32 => uint64) public rescueNonces;
    function _checkSignature(bytes32 digest, bytes calldata sig) internal view {
        require(ECDSA.recover(digest, sig) == signer && signer != address(0));
    }
    function rescue(bytes32 id, address to, uint64 nonce, bytes calldata sig) external {
        require(nonce == rescueNonces[id]);
        _checkSignature(keccak256(abi.encode(id, to, nonce, block.chainid)), sig);
        rescueNonces[id]++;
        (bool ok, ) = to.call{value: 1}("");
        require(ok);
    }
}

// Voucher consumed by recording the minted id against it (non-boolean "used" marker).
contract VoucherGateway {
    address public signer;
    mapping(bytes32 => uint256) public consumedInto;
    uint256 public issued;
    function claim(bytes32 inscription, address recipient, bytes calldata sig) external returns (uint256 id) {
        require(ECDSA.recover(keccak256(abi.encode(inscription, recipient, block.chainid)), sig) == signer);
        require(consumedInto[inscription] == 0);
        id = ++issued;
        consumedInto[inscription] = id;
    }
}

// Uniswap v4 hook keeper poke: settles pending claims, pays nobody.
interface IPoolManagerLike { function unlock(bytes calldata) external returns (bytes memory); }
contract HookPoke {
    IPoolManagerLike public poolManager; uint256 public pending;
    function sweep() external { if (pending != 0) poolManager.unlock(abi.encode(uint8(2))); }
}

// Sweep to an immutable SINK after claiming from ANOTHER contract named LOCKS (external call, not inlined).
interface ILocksLike { function claim(uint256) external; }
interface IERC20Like { function balanceOf(address) external view returns (uint256); function transfer(address, uint256) external returns (bool); }
contract LaunchSweep {
    ILocksLike public immutable LOCKS; IERC20Like public immutable RESERVE; address public immutable SINK; uint256 anchorLock;
    constructor(ILocksLike l, IERC20Like r, address s) { LOCKS = l; RESERVE = r; SINK = s; }
    function sweep() external returns (uint256 got) {
        uint256 before = RESERVE.balanceOf(address(this));
        LOCKS.claim(anchorLock);
        got = RESERVE.balanceOf(address(this)) - before;
        require(RESERVE.transfer(SINK, got));
    }
}
// an unrelated contract in the same bundle whose claim() pays the caller - must NOT leak into LaunchSweep
contract OtherLocks { mapping(address => uint256) bal;
    function claim(uint256 id) external { uint256 a = bal[msg.sender]; bal[msg.sender] = 0; (bool ok, ) = msg.sender.call{value: a}(""); require(ok); id; } }
