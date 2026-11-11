// SPDX-License-Identifier: MIT
// Real-world patterns that are NOT vulnerable (each was a false positive once).
pragma solidity ^0.4.24;

// BitGo WalletSimple style: replay protection via sequence ids (no variable called "nonce").
contract SequenceIdWallet {
    uint[10] recentSequenceIds;
    address[] public signers;
    function tryInsertSequenceId(uint sequenceId) private {
        uint lowest = 0;
        for (uint i = 0; i < 10; i++) { require(recentSequenceIds[i] != sequenceId); if (recentSequenceIds[i] < recentSequenceIds[lowest]) lowest = i; }
        recentSequenceIds[lowest] = sequenceId;
    }
    function getNetworkId() internal pure returns (string memory) { return "ETHER"; }
    function sendMultiSig(address to, uint value, uint expireTime, uint sequenceId, bytes32 r, bytes32 s, uint8 v) public {
        bytes32 operationHash = keccak256(abi.encodePacked(getNetworkId(), to, value, expireTime, sequenceId));
        address other = ecrecover(operationHash, v, r, s);
        require(other != address(0) && other != msg.sender);
        tryInsertSequenceId(sequenceId);
        to.transfer(value);
    }
}

// Gnosis classic MultiSigWallet: length arithmetic in admin-only / view code.
contract ClassicMultiSig {
    address[] public owners;
    mapping(address => bool) public isOwner;
    modifier onlyWallet() { require(msg.sender == address(this)); _; }
    function removeOwner(address owner) public onlyWallet {
        isOwner[owner] = false;
        for (uint i = 0; i < owners.length - 1; i++)
            if (owners[i] == owner) { owners[i] = owners[owners.length - 1]; break; }
        owners.length -= 1;
    }
    function getIds(uint from, uint to) public view returns (uint[] memory ids) { ids = new uint[](to - from); }
}

// ENS registry style: the public function itself has no modifier, but the helper it calls does.
contract RegistryLike {
    mapping(bytes32 => address) public owners;
    modifier authorised(bytes32 node) { require(owners[node] == msg.sender); _; }
    function setOwner(bytes32 node, address owner) public authorised(node) { owners[node] = owner; }
    function setRecord(bytes32 node, address owner) external { setOwner(node, owner); }
}

// Legacy positive guard wrapping the action (deposit wallets, 2016-era contracts).
contract LegacyDepositWallet {
    address owner;
    function LegacyDepositWallet() public { owner = msg.sender; }
    function kill() public { if (msg.sender == owner) selfdestruct(owner); }
}
